from fastapi import FastAPI, Request, HTTPException
from fastapi.routing import APIRoute
from fastapi.responses import Response, StreamingResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import httpx
import itertools
import os
import logging
import asyncio
import hashlib
from dotenv import load_dotenv
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path
from fastapi import Depends, status
from fastapi.security import APIKeyHeader
from ipaddress import ip_network, ip_address

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Enums and Data Classes ---
class HealthStatus(Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    DISABLED = "disabled"

@dataclass
class KeyStatus:
    key_id: str
    status: HealthStatus
    last_check: Optional[datetime] = None
    response_time: Optional[float] = None
    error_message: Optional[str] = None

@dataclass
class PlatformConfig:
    name: str
    display_name: str
    base_url: str
    api_path: str
    auth_header: str
    auth_format: str
    health_check_endpoint: str
    health_check_method: str = "GET"
    health_check_body: Optional[dict] = None
    enabled: bool = False
    keys: List[str] = None
    key_cycle: itertools.cycle = None

@dataclass
class KeyConfig:
    key: str
    is_root: bool = False
    daily_limit: int = 0
    hourly_limit: int = 0
    cooldown_seconds: int = 0
    expiry_date: Optional[str] = None
    enable_platform_whitelist: bool = False
    platform_whitelist: List[str] = None

    def __post_init__(self):
        if self.platform_whitelist is None:
            self.platform_whitelist = []

    def is_valid(self) -> bool:
        """Validate key (length and expiration)"""
        if len(self.key) < 8:
            return False
        if self.expiry_date == "0":
            return True
        try:
            expiry = datetime.strptime(self.expiry_date, "%Y-%m-%d")
            return expiry >= datetime.now()
        except (ValueError, TypeError):
            return True  # Invalid format is considered permanent

@dataclass
class AppConfig:
    enable_gui: bool = True
    enable_json: bool = True
    enable_key_validation: bool = False
    restrict_ip: bool = False
    allowed_ips: List[str] = None
    unhealthy_key_retry_minutes: int = 0
    port: int = 5000

# --- Platform Registry ---
class PlatformRegistry:
    def __init__(self):
        self.platforms: Dict[str, PlatformConfig] = {}
        self.clients: Dict[str, httpx.AsyncClient] = {}
        self.healthy_keys: Dict[str, List[str]] = {}
        self.unhealthy_keys: Dict[str, List[str]] = {}
        self.key_usage: Dict[str, Dict[str, Any]] = {}  # Track local API key usage

    def register_platform(self, config: PlatformConfig):
        self.platforms[config.name] = config
        self.healthy_keys[config.name] = config.keys.copy() if config.keys else []
        self.unhealthy_keys[config.name] = []
        logger.info("📝 Registering platform: %s (%s)", config.name, config.display_name)

    def get_platform(self, name: str) -> Optional[PlatformConfig]:
        return self.platforms.get(name)

    def get_enabled_platforms(self) -> Dict[str, PlatformConfig]:
        return {name: config for name, config in self.platforms.items() if config.enabled}

    def move_key_to_unhealthy(self, platform_name: str, key: str):
        if platform_name in self.healthy_keys and key in self.healthy_keys[platform_name]:
            self.healthy_keys[platform_name].remove(key)
            self.unhealthy_keys[platform_name].append(key)
            logger.info(f"🔴 Moving key {mask_api_key(key)} to {platform_name}'s unhealthy list")

    def retry_unhealthy_keys(self, platform_name: str):
        if platform_name in self.unhealthy_keys and self.unhealthy_keys[platform_name]:
            self.healthy_keys[platform_name].extend(self.unhealthy_keys[platform_name])
            self.unhealthy_keys[platform_name].clear()
            logger.info(f"🔄 Retrying {platform_name}'s unhealthy keys back to healthy list")

registry = PlatformRegistry()
templates = Jinja2Templates(directory="templates")

# --- Utility Functions ---
def mask_api_key(key: str) -> str:
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"

def generate_key_id(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:12]

async def test_api_key(platform: PlatformConfig, key: str) -> KeyStatus:
    key_id = generate_key_id(key)
    try:
        client = registry.clients.get(platform.name)
        if not client:
            return KeyStatus(
                key_id=key_id,
                status=HealthStatus.UNKNOWN,
                error_message="Client not initialized"
            )
        headers = {
            platform.auth_header: platform.auth_format.format(key=key),
            "Content-Type": "application/json"
        }
        start_time = asyncio.get_event_loop().time()
        if platform.health_check_method.upper() == "POST":
            response = await client.post(
                platform.health_check_endpoint,
                headers=headers,
                json=platform.health_check_body or {},
                timeout=10.0
            )
        else:
            response = await client.get(
                platform.health_check_endpoint,
                headers=headers,
                timeout=10.0
            )
        response_time = asyncio.get_event_loop().time() - start_time
        if response.status_code == 200:
            status = HealthStatus.HEALTHY
            error_msg = None
        elif response.status_code == 401:
            status = HealthStatus.UNHEALTHY
            error_msg = "Authentication failed"
        elif response.status_code == 403:
            status = HealthStatus.UNHEALTHY
            error_msg = "Insufficient permissions"
        else:
            status = HealthStatus.UNHEALTHY
            error_msg = f"HTTP {response.status_code}"
        return KeyStatus(
            key_id=key_id,
            status=status,
            last_check=datetime.now(),
            response_time=round(response_time * 1000, 2),
            error_message=error_msg
        )
    except asyncio.TimeoutError:
        return KeyStatus(
            key_id=key_id,
            status=HealthStatus.UNHEALTHY,
            last_check=datetime.now(),
            error_message="Request timeout"
        )
    except Exception as e:
        return KeyStatus(
            key_id=key_id,
            status=HealthStatus.UNHEALTHY,
            last_check=datetime.now(),
            error_message=str(e)[:100]
        )

# --- Load Configuration Files ---
def load_platforms():
    with open("platform.json", "r") as f:
        platforms = json.load(f)
    for p in platforms:
        keys = p.get("keys", [])
        resolved_keys = []
        for key in keys:
            # Check if it's an environment variable name
            env_key = os.environ.get(key)
            if env_key:  # If environment variable exists and is not empty
                resolved_keys.append(env_key)
                logger.info("🔑 Loading key from environment variable: %s -> %s", key, mask_api_key(env_key))
            elif key:  # If the original key is not empty
                resolved_keys.append(key)
                logger.info("🔑 Using key provided directly: %s", mask_api_key(key))
            else:
                logger.warning("⚠️ Invalid key or environment variable: %s (skipped)", key)
        if resolved_keys:
            p["keys"] = resolved_keys
            p["key_cycle"] = itertools.cycle(resolved_keys)
        else:
            p["keys"] = []
            logger.warning("⚠️ Platform %s has no valid keys", p["name"])
        registry.register_platform(PlatformConfig(**p))

def load_app_config() -> AppConfig:
    with open("config.json", "r") as f:
        config_data = json.load(f)
    return AppConfig(**config_data)

def load_key_configs() -> List[KeyConfig]:
    with open("key.json", "r") as f:
        key_data = json.load(f)
    return [KeyConfig(**k) for k in key_data if KeyConfig(**k).is_valid()]

# --- IP Restriction Check ---
def check_ip_restriction(request: Request, config: AppConfig):
    if not config.restrict_ip:
        return True
    client_ip = ip_address(request.client.host)
    if client_ip.is_loopback:
        return True
    for allowed_ip in config.allowed_ips or []:
        if client_ip in ip_network(allowed_ip):
            return True
    raise HTTPException(status_code=403, detail="IP not in allowed list")

# --- Key Validation (for proxy endpoints only) ---
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def validate_api_key(key: Optional[str] = Depends(api_key_header), request: Request = None):
    logger.info(f"🎯 Extracted API Key: {key if key else 'None'}")
    config = load_app_config()
    if not config.enable_key_validation:
        logger.info("✅ Key validation is disabled, passing directly")
        return True
    key_configs = load_key_configs()
    if not key:
        logger.error("❌ Missing API Key")
        raise HTTPException(status_code=401, detail="Missing API Key")
    
    # Manually remove the Bearer prefix
    if key.startswith("Bearer "):
        key = key[len("Bearer "):].strip()
        logger.info(f"🔧 Key after removing Bearer prefix: {mask_api_key(key)}")
    
    logger.info(f"🔍 Starting key validation: {mask_api_key(key)}")
    # Extract platform name from request path
    path = request.url.path
    platform_name = None
    if path.startswith("/api/v1"):
        platform_name = "openrouter"  # OpenRouter compatible route
    else:
        # Assuming path format is /platform_name/...
        parts = path.strip("/").split("/")
        if parts:
            platform_name = parts[0]
    
    logger.info(f"🔎 Detected platform name: {platform_name if platform_name else 'Not specified'}")
    
    for key_config in key_configs:
        logger.info(f"🔐 Matching key: {mask_api_key(key_config.key)}")
        if key_config.key == key:
            logger.info("✅ Key validation successful, checking other restrictions...")
            if key_config.is_root:
                logger.info("🌟 Root key, no restrictions applied")
                return True
            now = datetime.now()
            key_id = generate_key_id(key)
            usage = registry.key_usage.get(key_id, {"daily_count": 0, "hourly_count": 0, "last_used": None})
            
            # Check platform whitelist
            if key_config.enable_platform_whitelist and platform_name:
                if not key_config.platform_whitelist:
                    logger.error("⛔ Platform whitelist enabled but list is empty")
                    raise HTTPException(status_code=403, detail="Platform whitelist is empty, no platforms allowed")
                if platform_name not in key_config.platform_whitelist:
                    logger.error(f"⛔ Platform {platform_name} is not in the whitelist")
                    raise HTTPException(status_code=403, detail=f"Platform {platform_name} is not in the allowed whitelist")
                logger.info(f"✅ Platform {platform_name} is in the whitelist")
            
            # Check expiration date
            if key_config.expiry_date != "0":
                try:
                    expiry = datetime.strptime(key_config.expiry_date, "%Y-%m-%d")
                    if expiry < now:
                        logger.error("⛔ API Key has expired")
                        raise HTTPException(status_code=401, detail="API Key has expired")
                except ValueError:
                    logger.warning("⚠️ Invalid expiry_date format, treated as permanent")
                    key_config.expiry_date = "0"
            
            # Check daily limit
            if key_config.daily_limit > 0 and usage["daily_count"] >= key_config.daily_limit:
                logger.error("⛔ Daily usage limit exceeded")
                raise HTTPException(status_code=429, detail="Daily usage limit exceeded")
            
            # Check hourly limit
            if key_config.hourly_limit > 0 and usage["hourly_count"] >= key_config.hourly_limit:
                logger.error("⛔ Hourly usage limit exceeded")
                raise HTTPException(status_code=429, detail="Hourly usage limit exceeded")
            
            # Check cooldown period
            if key_config.cooldown_seconds > 0 and usage["last_used"]:
                if (now - usage["last_used"]).total_seconds() < key_config.cooldown_seconds:
                    logger.error("⛔ Request rate is too high")
                    raise HTTPException(status_code=429, detail="Request rate is too high")
            
            # Update usage count
            usage["daily_count"] += 1
            usage["hourly_count"] += 1
            usage["last_used"] = now
            registry.key_usage[key_id] = usage
            logger.info("✅ All checks passed, key is valid")
            return True
    
    logger.error("❌ Invalid API Key")
    raise HTTPException(status_code=401, detail="Invalid API Key")

# --- Application Lifecycle Management ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    load_platforms()
    config = load_app_config()
    enabled_platforms = registry.get_enabled_platforms()
    if not enabled_platforms:
        raise ValueError("⚠️ At least one platform with a valid API key is required!")
    create_platform_routes()
    logger.info("✅ Dynamic routes created successfully")
    for platform_name, config in enabled_platforms.items():
        registry.clients[platform_name] = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=httpx.Timeout(60.0),
            follow_redirects=True
        )
        logger.info("🚀 %s client initialized, loaded %d keys", 
                   config.display_name, len(config.keys))
    yield
    for client in registry.clients.values():
        if client:
            await client.aclose()
    logger.info("🛑 All clients closed, resources cleaned up")

app = FastAPI(
    title="Modular Multi-Platform AI API Proxy Server",
    description="A unified AI API proxy service with modular configuration support",
    version="1.0.1",
    lifespan=lifespan
)
# --- New GUI check function ---
# This function is used by all routes that require enable_gui to be checked
def check_enable_gui(config: AppConfig = Depends(load_app_config)):
    if not config.enable_gui:
        raise HTTPException(status_code=403, detail="GUI endpoint is not enabled")
    return True

# --- New generic JSON check function ---
# This function is used by all routes that require enable_json to be checked
def check_enable_json(config: AppConfig = Depends(load_app_config)):
    if not config.enable_json:
        raise HTTPException(status_code=403, detail="JSON endpoint is not enabled")
    return True

# --- Health Check Endpoint (no key validation needed) ---
# Added dependency on check_enable_json to control JSON output
@app.get("/health")
async def health_check(app_config: AppConfig = Depends(load_app_config), _=Depends(check_enable_json)):
    logger.info("🏥 Starting full health check...")
    enabled_platforms = registry.get_enabled_platforms()
    overall_status = HealthStatus.HEALTHY
    results = {}
    for platform_name, platform_config in enabled_platforms.items():
        logger.info("🔍 Checking platform: %s", platform_config.display_name)
        key_tasks = [test_api_key(platform_config, key) for key in platform_config.keys]
        key_results = await asyncio.gather(*key_tasks, return_exceptions=True)
        healthy_keys = 0
        key_statuses = []
        for i, result in enumerate(key_results):
            key = platform_config.keys[i]
            if isinstance(result, Exception):
                key_status = KeyStatus(
                    key_id=generate_key_id(key),
                    status=HealthStatus.UNKNOWN,
                    error_message=str(result)[:100]
                )
            else:
                key_status = result
                if key_status.status == HealthStatus.HEALTHY:
                    healthy_keys += 1
                else:
                    registry.move_key_to_unhealthy(platform_name, key)
            key_statuses.append({
                "key_id": key_status.key_id,
                "key_preview": mask_api_key(key),
                "status": key_status.status.value,
                "last_check": key_status.last_check.isoformat() if key_status.last_check else None,
                "response_time_ms": key_status.response_time,
                "error": key_status.error_message
            })
        total_keys = len(platform_config.keys)
        if healthy_keys == 0 and total_keys > 0:
            platform_status = HealthStatus.UNHEALTHY
            overall_status = HealthStatus.UNHEALTHY
        elif healthy_keys < total_keys:
            platform_status = HealthStatus.UNHEALTHY
        else:
            platform_status = HealthStatus.HEALTHY
        results[platform_name] = {
            "display_name": platform_config.display_name,
            "status": platform_status.value,
            "base_url": platform_config.base_url,
            "health_endpoint": f"{platform_config.base_url}{platform_config.health_check_endpoint}",
            "total_keys": total_keys,
            "healthy_keys": healthy_keys,
            "unhealthy_keys": total_keys - healthy_keys,
            "healthy_key_list": [mask_api_key(k) for k in registry.healthy_keys[platform_name]],
            "unhealthy_key_list": [mask_api_key(k) for k in registry.unhealthy_keys[platform_name]],
            "keys": key_statuses
        }
    # Move retry logic outside the loop, using app_config
    if app_config.unhealthy_key_retry_minutes > 0:
        async def retry_task():
            while True:
                await asyncio.sleep(app_config.unhealthy_key_retry_minutes * 60)
                for platform_name in enabled_platforms:
                    registry.retry_unhealthy_keys(platform_name)
        asyncio.create_task(retry_task())
    return {
        "timestamp": datetime.now().isoformat(),
        "overall_status": overall_status.value,
        "message": "Health check completed successfully ✨" if overall_status == HealthStatus.HEALTHY else "Issues detected ⚠️",
        "platforms": results,
        "summary": {
            "total_platforms": len(enabled_platforms),
            "healthy_platforms": sum(1 for p in results.values() if p["status"] == "healthy"),
            "total_keys": sum(p["total_keys"] for p in results.values()),
            "healthy_keys": sum(p["healthy_keys"] for p in results.values())
        }
    }

# Added dependency on check_enable_json
@app.get("/health/quick")
async def quick_health_check(config: AppConfig = Depends(load_app_config), _=Depends(check_enable_json)):
    enabled_platforms = registry.get_enabled_platforms()
    results = {}
    for platform_name, config in enabled_platforms.items():
        results[platform_name] = {
            "display_name": config.display_name,
            "status": "enabled",
            "total_keys": len(config.keys),
            "healthy_keys": len(registry.healthy_keys[platform_name]),
            "unhealthy_keys": len(registry.unhealthy_keys[platform_name]),
            "base_url": config.base_url
        }
    return {
        "timestamp": datetime.now().isoformat(),
        "status": "healthy",
        "message": "Quick check completed 🚀",
        "platforms": results
    }

# Modify here! Add _=Depends(check_enable_gui)
@app.get("/", response_class=HTMLResponse)
async def root_html(request: Request, app_config: AppConfig = Depends(load_app_config), _=Depends(check_enable_gui)):
    enabled_platforms = registry.get_enabled_platforms()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_config": app_config,
        "enabled_platforms": enabled_platforms,
        "service_name": "Modular Multi-Platform AI API Proxy Server",
        "version": "1.0.1",
        "features": [
            "🔄 API Key Rotation",
            "🏥 Comprehensive Health Checks",
            "🔐 Key Status Monitoring",
            "📊 Performance Statistics",
            "🚀 Modular Design"
        ]
    })

# JSON route
@app.get("/info")
async def root_json(app_config: AppConfig = Depends(load_app_config), _=Depends(check_enable_json)):
    enabled_platforms = registry.get_enabled_platforms()
    endpoints = {}
    for platform_name, platform_config in enabled_platforms.items():
        endpoints[platform_name] = f"/{platform_name}{platform_config.api_path}/*"
    endpoints.update({
        "health_full": "/health",
        "health_quick": "/health/quick"
    })
    if app_config.enable_gui:
        endpoints["dashboard"] = "/dashboard"
    if app_config.enable_json:
        endpoints["routes"] = "/routes"
        endpoints["info"] = "/info"
    return {
        "service": "Modular Multi-Platform AI API Proxy Server",
        "status": "Running 🎯",
        "version": "1.0.1",
        "enabled_platforms": list(enabled_platforms.keys()),
        "endpoints": endpoints,
        "features": [
            "🔄 API Key Rotation",
            "🏥 Comprehensive Health Checks",
            "🔐 Key Status Monitoring",
            "📊 Performance Statistics",
            "🚀 Modular Design"
        ]
    }

# --- Proxy Requests (requires key validation) ---
# Added dependency on check_enable_json
async def proxy_request(platform_name: str, path: str, request: Request, config: AppConfig = Depends(load_app_config), api_key: str = Depends(validate_api_key), _=Depends(check_enable_json)):
    """
    Proxies all API requests to the specified platform, handling authentication, streaming, etc.
    """
    
    # 1. Check IP restriction
    check_ip_restriction(request, config)
    
    # 2. Get platform configuration and client
    platform = registry.get_platform(platform_name)
    if not platform or not platform.enabled:
        raise HTTPException(status_code=404, detail=f"Platform {platform_name} is not enabled or supported")
    client = registry.clients[platform_name]
    
    # 3. Handle key rotation and health checks
    if not registry.healthy_keys[platform_name] and platform.keys:
        registry.retry_unhealthy_keys(platform_name)
        platform.key_cycle = itertools.cycle(platform.keys)
    current_key = next(platform.key_cycle)
    logger.info("🔄 [%s] Using API key: %s", platform.display_name, mask_api_key(current_key))
    
    # === Correction: Use a more concise and robust header strategy ===
    # Instead of copying headers from the original request, we manually create a clean header dictionary
    # This effectively prevents certain client headers from causing Cloudflare to return 400 Bad Request
    headers = {
        platform.auth_header: platform.auth_format.format(key=current_key),
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "keep-alive"
    }
    # ===============================================

    target_url = f"{platform.api_path}/{path}"
    logger.info("🚀 [%s] Request details:", platform.display_name)
    logger.info("   Method: %s", request.method)
    logger.info("   Target URL: %s", target_url)
    logger.info("   Content-Type: %s", headers.get("Content-Type", "Not set"))

    try:
        request_body = await request.body()
        is_streaming = False
        stream_source = "default"
        
        # 5. Determine if it's a streaming transfer
        if request_body and headers.get("Content-Type") == "application/json":
            try:
                body_data = json.loads(request_body.decode('utf-8'))
                if "stream" in body_data:
                    is_streaming = bool(body_data.get("stream", False))
                    stream_source = "request body"
                    logger.info("   📡 Detected stream from request body: %s", is_streaming)
                else:
                    query_stream = request.query_params.get("stream", "").lower()
                    if query_stream in ["true", "1", "yes"]:
                        is_streaming = True
                        stream_source = "query parameter"
                        logger.info("   📡 Detected stream from query parameter: %s", is_streaming)
                    else:
                        is_streaming = "chat/completions" in path.lower()
                        stream_source = "default (chat)" if is_streaming else "default (generic)"
                        logger.info("   🤖 %s", stream_source)
            except json.JSONDecodeError as e:
                logger.error("   ❌ JSON format error: %s", str(e))
                return Response(
                    content='{"error": "Request body is not a valid JSON format"}',
                    status_code=403,
                    media_type="application/json"
                )
        else:
            query_stream = request.query_params.get("stream", "").lower()
            if query_stream in ["true", "1", "yes"]:
                is_streaming = True
                stream_source = "query parameter"
                logger.info("   📡 Detected stream from query parameter: %s", is_streaming)
        
        logger.info("   Request body size: %d bytes", len(request_body) if request_body else 0)
        logger.info("   Streaming: %s (%s)", "Enabled 🌊" if is_streaming else "Disabled 📦", stream_source)

        # 6. Send streaming or single request
        if is_streaming:
            # Ensure headers for streaming are also correct
            headers["Accept"] = "text/event-stream"
            async def stream_response():
                try:
                    logger.info("🚀 [%s] Starting streaming connection...", platform.display_name)
                    async with client.stream(
                        method=request.method,
                        url=target_url,
                        headers=headers,
                        content=request_body,
                        params=dict(request.query_params),
                        timeout=60.0,
                    ) as response:
                        logger.info("📨 [%s] Streaming response status: %d", platform.display_name, response.status_code)
                        if response.status_code != 200:
                            error_content = await response.aread()
                            error_text = error_content.decode('utf-8', errors='ignore')
                            logger.error("❌ [%s] Streaming API returned error: %s", platform.display_name, error_text[:500])
                            yield error_content
                            return
                        start_time = asyncio.get_event_loop().time()
                        chunk_count = 0
                        async for raw_chunk in response.aiter_raw():
                            if raw_chunk:
                                chunk_count += 1
                                elapsed = asyncio.get_event_loop().time() - start_time
                                logger.info(
                                    "📦 [%s] Chunk #%d | Size: %d bytes | Time elapsed: %.3fs", 
                                    platform.display_name, chunk_count, len(raw_chunk), elapsed
                                )
                                yield raw_chunk
                        total_time = asyncio.get_event_loop().time() - start_time
                        logger.info("🏁 [%s] Streaming transfer complete | Total chunks: %d | Total time: %.3fs", 
                                   platform.display_name, chunk_count, total_time)
                except Exception as e:
                    logger.error("❌ [%s] Streaming transfer error: %s", platform.display_name, str(e))
                    yield f'data: {{"error": "Streaming transfer interrupted: {str(e)}"}}\n\n'.encode('utf-8')
            response_headers = {
                "Content-Type": "text/event-stream; charset=utf-8",
                "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
                "X-Accel-Buffering": "no",
                "X-Content-Type-Options": "nosniff",
                "Pragma": "no-cache",
                "Expires": "0",
                "Transfer-Encoding": "chunked"
            }
            return StreamingResponse(
                stream_response(),
                status_code=200,
                headers=response_headers,
                media_type="text/event-stream"
            )
        else:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=request_body,
                params=dict(request.query_params),
                timeout=60.0
            )
            logger.info("📨 [%s] Response status: %d", platform.display_name, response.status_code)
            if response.status_code != 200:
                error_content = response.content
                error_text = error_content.decode('utf-8', errors='ignore')
                logger.error("❌ [%s] API returned error: %s", platform.display_name, error_text[:500])
                return Response(
                    content=error_content,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.headers.get("Content-Type", "application/json")
                )
            response_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() not in ["content-encoding", "transfer-encoding", "content-length", "connection"]
            }
            logger.info("✅ [%s] Request successful 📦", platform.display_name)
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("Content-Type", "application/json")
            )
    except httpx.TimeoutException:
        logger.error("⏰ [%s] Request timeout", platform.display_name)
        return Response(
            content='{"error": "Request timeout, please try again later"}',
            status_code=504,
            media_type="application/json"
        )
    except Exception as e:
        logger.error("❌ [%s] Request failed: %s", platform.display_name, str(e))
        return Response(
            content=f'{{"error": "Proxy server request failed", "platform": "{platform_name}", "details": "{str(e)}"}}',
            status_code=500,
            media_type="application/json"
        )

# --- Dynamically Create Proxy Routes (requires key validation) ---
def create_platform_routes():
    enabled_platforms = registry.get_enabled_platforms()
    for platform_name, config in enabled_platforms.items():
        def make_handler(platform=platform_name):
            async def platform_handler(path: str, request: Request, config: AppConfig = Depends(load_app_config), api_key: str = Depends(validate_api_key), _=Depends(check_enable_json)):
                return await proxy_request(platform, path, request, config, api_key)
            return platform_handler
        handler = make_handler()
        app.api_route(
            f"/{platform_name}/{{path:path}}",
            methods=["GET", "POST"],
            name=f"proxy_{platform_name}"
        )(handler)
        logger.info("🛣️ Registering route: /%s", platform_name)


# --- Dashboard and Status Endpoints (no key validation needed) ---
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, _=Depends(check_enable_gui)):
    return templates.TemplateResponse("dashboard.html", {"request": request})


# --- Route List Endpoint (no key validation needed) ---
# Removed the original enable_json check and replaced with check_enable_json dependency
@app.get("/routes")
async def list_available_routes(config: AppConfig = Depends(load_app_config), _=Depends(check_enable_json)):
    enabled_platforms = registry.get_enabled_platforms()
    return {
        "available_endpoints": {
            platform_name: f"/{platform_name}{config.api_path}/*" 
            for platform_name, config in enabled_platforms.items()
        },
    }

# --- Test Streaming Endpoint (no key validation needed) ---
# Added dependency on check_enable_json
@app.get("/test/stream")
async def test_stream(_=Depends(check_enable_json)):
    async def fake_stream():
        test_chunks = [
            'data: {"id":"test-123","object":"chat.completion.chunk","choices":[{"delta":{"content":"Hello"}}]}\n\n',
            'data: {"id":"test-123","object":"chat.completion.chunk","choices":[{"delta":{"content":" there"}}]}\n\n',
            'data: {"id":"test-123","object":"chat.completion.chunk","choices":[{"delta":{"content":"!"}}]}\n\n',
            'data: {"id":"test-123","object":"chat.completion.chunk","choices":[{"delta":{"content":" How"}}]}\n\n',
            'data: {"id":"test-123","object":"chat.completion.chunk","choices":[{"delta":{"content":" are"}}]}\n\n',
            'data: {"id":"test-123","object":"chat.completion.chunk","choices":[{"delta":{"content":" you"}}]}\n\n',
            'data: {"id":"test-123","object":"chat.completion.chunk","choices":[{"delta":{"content":"?"}}]}\n\n',
            'data: [DONE]\n\n'
        ]
        for i, chunk in enumerate(test_chunks):
            logger.info(f"🧪 Sending test chunk #{i+1}: {chunk.strip()}")
            yield chunk.encode('utf-8')
            await asyncio.sleep(0.5)
    return StreamingResponse(
        fake_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

# Added dependency on check_enable_json
@app.get("/test/stream-fast")
async def test_stream_fast(_=Depends(check_enable_json)):
    async def fast_stream():
        test_chunks = [
            'data: {"choices":[{"delta":{"content":"A"}}]}\n\n',
            'data: {"choices":[{"delta":{"content":"B"}}]}\n\n',
            'data: {"choices":[{"delta":{"content":"C"}}]}\n\n',
            'data: {"choices":[{"delta":{"content":"D"}}]}\n\n',
            'data: {"choices":[{"delta":{"content":"E"}}]}\n\n',
            'data: [DONE]\n\n'
        ]
        for i, chunk in enumerate(test_chunks):
            logger.info(f"⚡ Fast sending chunk #{i+1}")
            yield chunk.encode('utf-8')
    return StreamingResponse(
        fast_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

ROUTE_DESCRIPTIONS = {
    "/": "Service Overview (JSON)",
    "/status": "Current Status (This Page)",
    "/health": "Full Health Check (All API Keys)",
    "/health/quick": "Quick Check (No Key Testing)",
    "/dashboard": "GUI Monitoring Dashboard (HTML)",
    "/routes": "Show List of Available Proxy Platforms (JSON)",
    "/test/stream": "Test Streaming Response (Slow)",
    "/test/stream-fast": "Test Streaming Response (Fast)"
}

if __name__ == "__main__":
    import uvicorn
    load_platforms()
    config = load_app_config()
    create_platform_routes()
    print("🚀 Starting modular multi-platform AI API proxy server...")
    print("📝 Supported features:")
    print("   🏥 Full Health Check: http://localhost:{}/health".format(config.port))
    print("   ⚡ Quick Health Check: http://localhost:{}/health/quick".format(config.port))
    print("   📊 Service Info:     http://localhost:{}/".format(config.port))
    print("   🔗 API endpoints are dynamically generated based on configuration...")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=config.port,
        reload=True,
        log_level="info"
    )