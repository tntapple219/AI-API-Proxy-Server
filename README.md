# Modular Multi-Platform AI API Proxy Server

![Project Status](https://img.shields.io/badge/status-active-success.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A unified and modular AI API proxy service designed to streamline interactions with various AI platforms. This server provides a single entry point for multiple AI services, offering features like API key rotation, comprehensive health checks, key status monitoring, and dynamic routing.

## Features

-   **API Key Rotation**: Automatically cycles through a list of API keys for each platform to distribute load and manage rate limits.
-   **Comprehensive Health Checks**: Monitors the health of each configured API key across all platforms, identifying unhealthy keys and retrying them periodically.
-   **Key Status Monitoring**: Provides detailed insights into the status of individual API keys, including last check time, response time, and error messages.
-   **Dynamic Routing**: Automatically generates API endpoints for each configured platform, allowing seamless integration.
-   **IP Restriction**: Restrict access to the proxy server based on a whitelist of IP addresses.
-   **Modular Configuration**: Easily add or remove AI platforms and API keys via simple JSON configuration files.
-   **Web-based Dashboard**: A user-friendly GUI to monitor the real-time status of all platforms and API keys.
-   **Streaming Support**: Handles streaming responses for AI models that support it.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/tntapple219/AI-API-Proxy-Server.git
    cd AI-API-Proxy-Server.git
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    python -m venv venv
    ./venv/Scripts/activate  # On Windows
    # source venv/bin/activate # On Linux/macOS
    pip install -r requirements.txt
    ```
    *(Note: `requirements.txt` is not provided, you might need to create it based on `main.py` imports: `fastapi`, `uvicorn`, `httpx`, `python-dotenv`, `openai`, `python-multipart`, `ipaddress`)*

## Configuration

The server uses several JSON files and an `.env` file for configuration.

### `.env` File

Create a `.env` file in the project root. This file is used to store sensitive API keys or other environment-specific variables. An example is provided in `.env.example`.

```ini
# Example API Key for a platform named 'my_platform'
MY_PLATFORM_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### `config.json`

This file contains general application settings.

```json
{
    "enable_gui": true,
    "enable_json": true,
    "enable_key_validation": true,
    "restrict_ip": false,
    "allowed_ips": ["192.168.1.0/24", "10.0.0.0/8"],
    "unhealthy_key_retry_minutes": 60,
    "port": 5000
}
```

-   `enable_gui`: (boolean) Enable or disable the web-based dashboard.
-   `enable_json`: (boolean) Enable or disable JSON info endpoints.
-   `enable_key_validation`: (boolean) Enable or disable API key validation for proxy endpoints.
-   `restrict_ip`: (boolean) Enable or disable IP address restriction.
-   `allowed_ips`: (array of strings) List of allowed IP addresses or CIDR ranges if `restrict_ip` is true.
-   `unhealthy_key_retry_minutes`: (integer) Interval in minutes to retry unhealthy API keys.
-   `port`: (integer) The port on which the server will listen.

### `key.json`

This file defines the API keys that can be used to access the proxy server itself (not the upstream AI platforms). These are your internal keys for managing access to *this* proxy.

```json
[
    {
        "key": "root_key",
        "is_root": true,
        "daily_limit": 0,
        "hourly_limit": 0,
        "cooldown_seconds": 0,
        "expiry_date": "0",
        "enable_platform_whitelist": false,
        "platform_whitelist": []
    }
]
```

-   `key`: (string) The actual API key string.
-   `is_root`: (boolean) If true, this key bypasses all limits and restrictions.
-   `daily_limit`: (integer) Maximum daily requests for this key (0 for unlimited).
-   `hourly_limit`: (integer) Maximum hourly requests for this key (0 for unlimited).
-   `cooldown_seconds`: (integer) Cooldown period in seconds between requests for this key.
-   `expiry_date`: (string) Expiry date in `YYYY-MM-DD` format ("0" for never expires).
-   `enable_platform_whitelist`: (boolean) If true, `platform_whitelist` will be enforced.
-   `platform_whitelist`: (array of strings) List of platform names this key is allowed to access.

### `platform.json`

This file configures the upstream AI platforms that the proxy will interact with.

```json
[
    {
        "name": "openrouter",
        "display_name": "OpenRouter AI",
        "base_url": "https://openrouter.ai/api",
        "api_path": "/v1",
        "auth_header": "Authorization",
        "auth_format": "Bearer {key}",
        "health_check_endpoint": "/models",
        "health_check_method": "GET",
        "enabled": true,
        "keys": ["OPENROUTER_API_KEY_1", "OPENROUTER_API_KEY_2"]
    },
    {
        "name": "openai",
        "display_name": "OpenAI",
        "base_url": "https://api.openai.com",
        "api_path": "/v1",
        "auth_header": "Authorization",
        "auth_format": "Bearer {key}",
        "health_check_endpoint": "/models",
        "health_check_method": "GET",
        "enabled": false,
        "keys": ["OPENAI_API_KEY"]
    }
]
```

-   `name`: (string) Unique identifier for the platform (used in routes, e.g., `/openrouter/chat/completions`).
-   `display_name`: (string) Human-readable name for the platform.
-   `base_url`: (string) The base URL of the upstream API.
-   `api_path`: (string) The API path segment (e.g., `/v1`).
-   `auth_header`: (string) The HTTP header name for authentication (e.g., `Authorization`).
-   `auth_format`: (string) Format string for the authentication header value, with `{key}` as a placeholder for the API key.
-   `health_check_endpoint`: (string) Endpoint to use for health checks.
-   `health_check_method`: (string) HTTP method for health checks (default: `GET`).
-   `enabled`: (boolean) Whether this platform is enabled for proxying.
-   `keys`: (array of strings) List of API keys for this platform. These can be direct key strings or names of environment variables (e.g., `OPENROUTER_API_KEY_1` will be resolved from `.env`).

## Usage

### Running the Server

```bash
python main.py
```

The server will start on the port specified in `config.json` (default: `5000`).

### API Endpoints

-   **Service Information**: `GET /info`
    Returns general service status and a list of available endpoints.

-   **Health Check (Full)**: `GET /health`
    Performs a detailed health check on all configured platforms and their API keys.

-   **Health Check (Quick)**: `GET /health/quick`
    Provides a quick overview of enabled platforms and key counts without individual key testing.

-   **Web Dashboard**: `GET /dashboard`
    Access the real-time monitoring dashboard (if `enable_gui` is true).

-   **Proxy Endpoints**: Dynamically generated based on `platform.json`.
    For a platform named `[platform_name]` with `api_path` `[api_path]`, requests will be proxied from:
    `http://localhost:5000/[platform_name][api_path]/<upstream_path>`
    
    Example for `openrouter`:
    `POST http://localhost:5000/openrouter/v1/chat/completions`
    
    Ensure you include an `Authorization: Bearer YOUR_PROXY_KEY` header, where `YOUR_PROXY_KEY` is one of the keys defined in `key.json`.

## Development

### Project Structure

```
.env
config.json
key.json
main.py
platform.json
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. (Note: LICENSE file is not provided, please create one if needed.)
