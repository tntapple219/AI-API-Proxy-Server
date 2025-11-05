from fastapi import FastAPI, Request, HTTPException
from fastapi.routing import APIRoute
from fastapi.responses import Response, StreamingResponse, HTMLResponse
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
from fastapi.middleware.cors import CORSMiddleware
from openai import AsyncOpenAI
import openai

load_dotenv()

# Configure logging for the application.
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
        """Checks if the API key is valid (length and expiry date)."""
        if len(self.key) < 8:
            return False
        if self.expiry_date == "0":
            return True
        try:
            expiry = datetime.strptime(self.expiry_date, "%Y-%m-%d")
            return expiry >= datetime.now()
        except (ValueError, TypeError):
            return True  # Treat invalid format as never expiring

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
        self.clients: Dict[str, AsyncOpenAI] = {}
        self.platforms: Dict[str, PlatformConfig] = {}
        self.healthy_keys: Dict[str, List[str]] = {}
        self.unhealthy_keys: Dict[str, List[str]] = {}
        self.key_usage: Dict[str, Dict[str, Any]] = {}  # Tracks local API key usage

    def register_platform(self, config: PlatformConfig):
        self.platforms[config.name] = config
        self.healthy_keys[config.name] = config.keys.copy() if config.keys else []
        self.unhealthy_keys[config.name] = []
        logger.info("Registered platform: %s (%s)", config.name, config.display_name)

    def get_platform(self, name: str) -> Optional[PlatformConfig]:
        return self.platforms.get(name)

    def get_enabled_platforms(self) -> Dict[str, PlatformConfig]:
        return {name: config for name, config in self.platforms.items() if config.enabled}

    def move_key_to_unhealthy(self, platform_name: str, key: str):
        if platform_name in self.healthy_keys and key in self.healthy_keys[platform_name]:
            self.healthy_keys[platform_name].remove(key)
            if key not in self.unhealthy_keys[platform_name]:
                self.unhealthy_keys[platform_name].append(key)
            logger.info(f"Key {mask_api_key(key)} moved to {platform_name}'s unhealthy list")

    def retry_unhealthy_keys(self, platform_name: str):
        if platform_name in self.unhealthy_keys and self.unhealthy_keys[platform_name]:
            self.healthy_keys[platform_name].extend(self.unhealthy_keys[platform_name])
            self.unhealthy_keys[platform_name].clear()
            logger.info(f"Retrying {platform_name}'s unhealthy keys back to healthy list")

registry = PlatformRegistry()

# --- Utility Functions ---
def mask_api_key(key: str) -> str:
    """Masks an API key for logging purposes."""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"

def generate_key_id(key: str) -> str:
    """Generates a unique ID for an API key using SHA256 hashing."""
    return hashlib.sha256(key.encode()).hexdigest()[:12]

async def test_api_key(platform: PlatformConfig, key: str) -> KeyStatus:
    """Tests the health status of an API key using an OpenAI-compatible client."""
    key_id = generate_key_id(key)
    
    client = AsyncOpenAI(
        api_key=key,
        base_url=f"{platform.base_url}{platform.api_path}",
        timeout=20.0
    )
    
    start_time = asyncio.get_event_loop().time()
    response_time = None
    status = HealthStatus.UNKNOWN
    error_msg = None

    try:
        await client.models.list()
        response_time = asyncio.get_event_loop().time() - start_time
        status = HealthStatus.HEALTHY
        
    except openai.AuthenticationError:
        status = HealthStatus.UNHEALTHY
        error_msg = "Authentication failed"
    except openai.PermissionDeniedError:
        status = HealthStatus.UNHEALTHY
        error_msg = "Permission denied"
    except asyncio.TimeoutError:
        status = HealthStatus.UNHEALTHY
        error_msg = "Request timed out"
    except Exception as e:
        status = HealthStatus.UNHEALTHY
        error_msg = str(e)[:100]
    finally:
        await client.close()

    return KeyStatus(
        key_id=key_id,
        status=status,
        last_check=datetime.now(),
        response_time=round(response_time * 1000, 2) if response_time is not None else None,
        error_message=error_msg
    )

# --- Configuration Loading Functions ---
def load_platforms():
    """Loads platform configurations from 'platform.json' and resolves API keys from environment variables."""
    with open("platform.json", "r") as f:
        platforms = json.load(f)
    for p in platforms:
        keys = p.get("keys", [])
        resolved_keys = []
        for key in keys:
            env_key = os.environ.get(key)
            if env_key:
                resolved_keys.append(env_key)
                logger.info("Loaded Key from environment variable: %s -> %s", key, mask_api_key(env_key))
            elif key:
                resolved_keys.append(key)
                logger.info("Using directly provided Key: %s", mask_api_key(key))
            else:
                logger.warning("Invalid Key or environment variable: %s (Skipping)", key)
        
        p["keys"] = resolved_keys
        p["key_cycle"] = itertools.cycle(resolved_keys) if resolved_keys else None
        if not resolved_keys:
            logger.warning("No valid Keys for platform: %s", p["name"])
        
        registry.register_platform(PlatformConfig(**p))

def load_app_config() -> AppConfig:
    """Loads application configuration from 'config.json'."""
    with open("config.json", "r") as f:
        config_data = json.load(f)
    return AppConfig(**config_data)

def load_key_configs() -> List[KeyConfig]:
    """Loads API key configurations from 'key.json'."""
    with open("key.json", "r") as f:
        key_data = json.load(f)
    return [KeyConfig(**k) for k in key_data if KeyConfig(**k).is_valid()]

# --- IP Restriction Check ---
def check_ip_restriction(request: Request, config: AppConfig):
    """Checks if the client's IP address is allowed based on the application configuration."""
    if not config.restrict_ip:
        return
    client_ip = ip_address(request.client.host)
    if client_ip.is_loopback:
        return
    for allowed_ip in config.allowed_ips or []:
        if client_ip in ip_network(allowed_ip):
            return
    raise HTTPException(status_code=403, detail="IP not in allowed list")

# --- API Key Validation (for proxy endpoints only) ---
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def validate_api_key(key: Optional[str] = Depends(api_key_header), request: Request = None):
    """Validates the provided API key against configured rules (limits, expiry, platform whitelist)."""
    logger.info(f"Extracted API Key: {key if key else 'None'}")
    config = load_app_config()
    if not config.enable_key_validation:
        logger.info("✅ Key validation disabled, proceeding without validation")
        return True
    
    key_configs = load_key_configs()
    if not key:
        logger.error("Missing API Key")
        raise HTTPException(status_code=401, detail="Missing API Key")
    
    if key.startswith("Bearer "):
        key = key[len("Bearer "):].strip()
        logger.info(f"Key after removing Bearer prefix: {mask_api_key(key)}")
    
    logger.info(f"Starting key validation for: {mask_api_key(key)}")
    
    path = request.url.path
    platform_name = None
    if path.startswith("/api/v1"):
        platform_name = "openrouter"
    else:
        parts = path.strip("/").split("/")
        if parts:
            platform_name = parts[0]
    
    logger.info(f"Detected platform name: {platform_name if platform_name else 'Not specified'}")
    
    for key_config in key_configs:
        logger.info(f"Comparing with configured Key: {mask_api_key(key_config.key)}")
        if key_config.key == key:
            logger.info("Key matched, checking other restrictions...")
            if key_config.is_root:
                logger.info("Root Key, bypassing all restrictions")
                return True
            
            now = datetime.now()
            key_id = generate_key_id(key)
            usage = registry.key_usage.get(key_id, {"daily_count": 0, "hourly_count": 0, "last_used": None})
            
            if key_config.enable_platform_whitelist and platform_name:
                if not key_config.platform_whitelist:
                    logger.error("Platform whitelist enabled but list is empty")
                    raise HTTPException(status_code=403, detail="Platform whitelist is empty, no platforms allowed")
                if platform_name not in key_config.platform_whitelist:
                    logger.error(f"Platform {platform_name} not in whitelist")
                    raise HTTPException(status_code=403, detail=f"Platform {platform_name} is not in the allowed whitelist")
                logger.info(f"Platform {platform_name} is in the whitelist")
            
            if key_config.expiry_date != "0":
                try:
                    expiry = datetime.strptime(key_config.expiry_date, "%Y-%m-%d")
                    if expiry < now:
                        logger.error("API Key has expired")
                        raise HTTPException(status_code=401, detail="API Key has expired")
                except ValueError:
                    logger.warning("Invalid expiry_date format, treating as never expiring")
            
            if key_config.daily_limit > 0 and usage["daily_count"] >= key_config.daily_limit:
                logger.error("Daily usage limit exceeded")
                raise HTTPException(status_code=429, detail="Daily usage limit exceeded")
            
            if key_config.hourly_limit > 0 and usage["hourly_count"] >= key_config.hourly_limit:
                logger.error("Hourly usage limit exceeded")
                raise HTTPException(status_code=429, detail="Hourly usage limit exceeded")
            
            if key_config.cooldown_seconds > 0 and usage["last_used"]:
                if (now - usage["last_used"]).total_seconds() < key_config.cooldown_seconds:
                    logger.error("Request rate limited")
                    raise HTTPException(status_code=429, detail="Request rate limited")
            
            usage["daily_count"] += 1
            usage["hourly_count"] += 1
            usage["last_used"] = now
            registry.key_usage[key_id] = usage
            logger.info("All checks passed, Key is valid")
            return True
            
    logger.error("Invalid API Key")
    raise HTTPException(status_code=401, detail="Invalid API Key")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages the startup and shutdown events of the FastAPI application."""
    load_platforms()
    config = load_app_config()
    enabled_platforms = registry.get_enabled_platforms()
    
    for platform_name, platform_config in enabled_platforms.items():
        registry.clients[platform_name] = httpx.AsyncClient(
            base_url=platform_config.base_url,
            follow_redirects=True,
            http2=True
        )
        logger.info("HTTP client created for platform '%s'", platform_name)

    if not enabled_platforms:
        raise ValueError("At least one platform with valid API Keys is required!")
    
    if config.unhealthy_key_retry_minutes > 0:
        async def retry_task():
            while True:
                await asyncio.sleep(config.unhealthy_key_retry_minutes * 60)
                for platform_name in enabled_platforms:
                    registry.retry_unhealthy_keys(platform_name)
        asyncio.create_task(retry_task())
        logger.info("Unhealthy key retry task enabled, runs every %d minutes", config.unhealthy_key_retry_minutes)
    
    create_platform_routes()
    logger.info("Dynamic routes created")
    
    yield
    
    for client in registry.clients.values():
        await client.aclose()
    logger.info("Application shutdown, resources cleaned up")

app = FastAPI(
    title="Modular Multi-Platform AI API Proxy Server",
    description="A unified AI API proxy service supporting modular configuration",
    version="1.0.1",
    lifespan=lifespan
)

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- GUI and JSON Feature Check Functions ---
def check_enable_gui(config: AppConfig = Depends(load_app_config)):
    """Dependency to check if GUI endpoints are enabled."""
    if not config.enable_gui:
        raise HTTPException(status_code=403, detail="GUI endpoints are not enabled")

def check_enable_json(config: AppConfig = Depends(load_app_config)):
    """Dependency to check if JSON endpoints are enabled."""
    if not config.enable_json:
        raise HTTPException(status_code=403, detail="JSON endpoints are not enabled")

# --- Health Check Endpoints ---
@app.get("/health", dependencies=[Depends(check_enable_json)])
async def health_check():
    """Performs a comprehensive health check across all enabled platforms and their API keys."""
    logger.info("Starting full health check...")
    enabled_platforms = registry.get_enabled_platforms()
    overall_status = HealthStatus.HEALTHY
    results = {}
    
    for platform_name, platform_config in enabled_platforms.items():
        logger.info("Checking platform: %s", platform_config.display_name)
        key_tasks = [test_api_key(platform_config, key) for key in platform_config.keys]
        key_results = await asyncio.gather(*key_tasks, return_exceptions=True)
        
        healthy_keys_count = 0
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
                    healthy_keys_count += 1
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
        platform_status = HealthStatus.HEALTHY
        if total_keys > 0 and healthy_keys_count == 0:
            platform_status = HealthStatus.UNHEALTHY
            overall_status = HealthStatus.UNHEALTHY
        elif healthy_keys_count < total_keys:
            platform_status = HealthStatus.UNHEALTHY
            
        results[platform_name] = {
            "display_name": platform_config.display_name,
            "status": platform_status.value,
            "base_url": platform_config.base_url,
            "health_endpoint": f"{platform_config.base_url}{platform_config.health_check_endpoint}",
            "total_keys": total_keys,
            "healthy_keys": healthy_keys_count,
            "unhealthy_keys": total_keys - healthy_keys_count,
            "healthy_key_list": [mask_api_key(k) for k in registry.healthy_keys.get(platform_name, [])],
            "unhealthy_key_list": [mask_api_key(k) for k in registry.unhealthy_keys.get(platform_name, [])],
            "keys": key_statuses
        }
        
    return {
        "timestamp": datetime.now().isoformat(),
        "overall_status": overall_status.value,
        "message": "Health check completed" if overall_status == HealthStatus.HEALTHY else "Issues detected",
        "platforms": results,
        "summary": {
            "total_platforms": len(enabled_platforms),
            "healthy_platforms": sum(1 for p in results.values() if p["status"] == "healthy"),
            "total_keys": sum(p["total_keys"] for p in results.values()),
            "healthy_keys": sum(p["healthy_keys"] for p in results.values())
        }
    }

@app.get("/health/quick", dependencies=[Depends(check_enable_json)])
async def quick_health_check():
    """Performs a quick health check, returning basic status for enabled platforms."""
    enabled_platforms = registry.get_enabled_platforms()
    results = {}
    for platform_name, config in enabled_platforms.items():
        results[platform_name] = {
            "display_name": config.display_name,
            "status": "enabled",
            "total_keys": len(config.keys),
            "healthy_keys": len(registry.healthy_keys.get(platform_name, [])),
            "unhealthy_keys": len(registry.unhealthy_keys.get(platform_name, [])),
            "base_url": config.base_url
        }
    return {
        "timestamp": datetime.now().isoformat(),
        "status": "healthy",
        "message": "Quick check completed",
        "platforms": results
    }

@app.get("/info", dependencies=[Depends(check_enable_json)])
async def root_json(app_config: AppConfig = Depends(load_app_config)):
    """Returns general service information and available endpoints in JSON format."""
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
        "status": "Running",
        "version": "1.0.1",
        "enabled_platforms": list(enabled_platforms.keys()),
        "endpoints": endpoints,
        "features": [
            "API Key Rotation",
            "Comprehensive Health Checks",
            "Key Status Monitoring",
            "Performance Statistics",
            "Modular Design"
        ]
    }

# --- Proxy Request Function ---
async def proxy_request(platform: PlatformConfig, path: str, request: Request, config: AppConfig, registry: PlatformRegistry):
    """Proxies all API requests to the specified platform, handling authentication, streaming, and error management."""
    check_ip_restriction(request, config)
    
    client = registry.clients.get(platform.name)
    if not client:
        raise HTTPException(status_code=500, detail=f"Client for platform '{platform.name}' not initialized.")
    
    if not registry.healthy_keys.get(platform.name) and platform.keys:
        registry.retry_unhealthy_keys(platform.name)
        platform.key_cycle = itertools.cycle(platform.keys)
    
    if not platform.key_cycle:
        raise HTTPException(status_code=503, detail=f"No healthy API keys available for platform: {platform.name}")

    current_key = next(platform.key_cycle)
    logger.info("[%s] Using API Key: %s", platform.display_name, mask_api_key(current_key))
    
    headers = {
        platform.auth_header: platform.auth_format.format(key=current_key),
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "keep-alive"
    }
    headers.pop("Accept-Encoding", None)

    target_url = f"{platform.api_path}/{path}"
    logger.info("[%s] Request details:", platform.display_name)
    logger.info("   Method: %s", request.method)
    logger.info("   Target URL: %s", target_url)

    try:
        request_body = await request.body()
        is_streaming = False
        
        if request_body and headers.get("Content-Type") == "application/json":
            try:
                body_data = json.loads(request_body.decode('utf-8'))
                is_streaming = body_data.get("stream", False)
            except json.JSONDecodeError:
                logger.error("   JSON format error")
                return Response('{"error": "Invalid JSON format in request body"}', status_code=400, media_type="application/json")
        
        logger.info("   Streaming: %s", "Enabled" if is_streaming else "Disabled")

        if is_streaming:
            headers["Accept"] = "text/event-stream"
            
            async def stream_response():
                try:
                    async with client.stream(
                        method=request.method,
                        url=target_url,
                        headers=headers,
                        content=request_body,
                        params=dict(request.query_params),
                        timeout=60.0,
                    ) as response:
                        logger.info("[%s] Streaming response status: %d", platform.display_name, response.status_code)
                        async for chunk in response.aiter_bytes():
                            yield chunk
                except Exception as e:
                    logger.error("[%s] Streaming error: %s", platform.display_name, str(e))
                    yield f'data: {{"error": "Streaming interrupted: {str(e)}"}}'.encode('utf-8')
            
            response_headers = {
                "Content-Type": "text/event-stream; charset=utf-8",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            }
            return StreamingResponse(stream_response(), headers=response_headers, media_type="text/event-stream")
        
        else:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=request_body,
                params=dict(request.query_params),
                timeout=60.0
            )
            logger.info("[%s] Response status: %d", platform.display_name, response.status_code)
            
            response_content = await response.aread()
            response_headers = {k: v for k, v in response.headers.items() if k.lower() not in ["content-encoding", "transfer-encoding", "content-length"]}
            
            return Response(
                content=response_content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("Content-Type", "application/json")
            )
            
    except httpx.TimeoutException:
        logger.error("[%s] Request timed out", platform.display_name)
        return Response('{"error": "Request timed out"}', status_code=504, media_type="application/json")
    except Exception as e:
        logger.error("[%s] Request failed: %s", platform.display_name, str(e))
        return Response(f'{{"error": "Proxy server error", "details": "{str(e)}"}}', status_code=500, media_type="application/json")

def get_registry() -> PlatformRegistry:
    """Returns the singleton instance of the PlatformRegistry."""
    return registry

# --- Dynamically Create Proxy Routes ---
def create_platform_routes():
    """Dynamically creates API routes for each enabled platform."""
    enabled_platforms = registry.get_enabled_platforms()
    for platform_name, platform_config in enabled_platforms.items():
        
        def make_handler(platform=platform_config):
            async def platform_handler(
                path: str,
                request: Request,
                config: AppConfig = Depends(load_app_config),
                api_key_validated: bool = Depends(validate_api_key),
                reg: PlatformRegistry = Depends(get_registry)
            ):
                return await proxy_request(platform, path, request, config, reg)
            return platform_handler

        handler = make_handler()
        app.api_route(
            f"/{platform_name}/{{path:path}}",
            methods=["GET", "POST", "OPTIONS"],
            name=f"proxy_{platform_name}"
        )(handler)
        logger.info("Registered route: /%s/*", platform_name)

# --- Route Listing Endpoint ---
@app.get("/routes", dependencies=[Depends(check_enable_json)])
async def list_available_routes():
    """Lists all dynamically generated proxy routes."""
    enabled_platforms = registry.get_enabled_platforms()
    return {
        "available_endpoints": {
            name: f"/{name}{config.api_path}/*" 
            for name, config in enabled_platforms.items()
        }
    }

# --- Test Streaming Endpoints ---
@app.get("/test/stream", dependencies=[Depends(check_enable_json)])
async def test_stream():
    """Provides a slow streaming test endpoint."""
    async def fake_stream():
        chunks = [
            'data: {"id":"test-1","content":"Hello"}',
            'data: {"id":"test-2","content":" world"}',
            'data: {"id":"test-3","content":"!"}',
            'data: [DONE]'
        ]
        for chunk in chunks:
            yield chunk.encode('utf-8') + b'\n\n'
            await asyncio.sleep(0.5)
    return StreamingResponse(fake_stream(), media_type="text/event-stream")

@app.get("/test/stream-fast", dependencies=[Depends(check_enable_json)])
async def test_stream_fast():
    """Provides a fast streaming test endpoint."""
    async def fast_stream():
        chunks = [
            'data: {"content":"A"}', 'data: {"content":"B"}',
            'data: {"content":"C"}', 'data: [DONE]'
        ]
        for chunk in chunks:
            yield chunk.encode('utf-8') + b'\n\n'
    return StreamingResponse(fast_stream(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    config = load_app_config()
    print("Starting Modular Multi-Platform AI API Proxy Server...")
    print(f"   Service Info: http://localhost:{config.port}/info")
    print(f"   Full Health Check: http://localhost:{config.port}/health")
    print(f"   Quick Health Check: http://localhost:{config.port}/health/quick")
    print("   API endpoints will be dynamically generated based on configuration...")
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=config.port,
        reload=True,
        log_level="info"
    )