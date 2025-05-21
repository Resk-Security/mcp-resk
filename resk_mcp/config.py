# resk_mcp/config.py
import os
import yaml
from dotenv import load_dotenv
from typing import Any, Dict, Optional

# Load .env file first to make environment variables available for overrides
load_dotenv()

CONFIG_FILE_PATH = os.getenv("RESK_MCP_CONFIG_FILE", "config.yaml")

class Settings:
    def __init__(self, config_data: Dict[str, Any]):
        # Security settings
        jwt_config = config_data.get("jwt", {})
        # Check for both "secret" and "JWT_SECRET" for backward compatibility
        self.jwt_secret: Optional[str] = os.getenv("JWT_SECRET") or jwt_config.get("secret") or jwt_config.get("JWT_SECRET")
        self.jwt_algorithm: str = os.getenv("JWT_ALGORITHM") or jwt_config.get("algorithm", "HS256")
        self.jwt_expiration_minutes: int = int(os.getenv("JWT_EXPIRATION_MINUTES") or jwt_config.get("expiration_minutes", 30))

        rate_limit_config = config_data.get("rate_limit", {})
        self.rate_limit: str = os.getenv("RATE_LIMIT") or rate_limit_config.get("default", "100/minute")

        # Context management
        context_config = config_data.get("context", {})
        self.max_token_per_request: int = int(os.getenv("MAX_TOKEN_PER_REQUEST") or context_config.get("max_tokens", 4000))
        self.chars_per_token_approx: int = int(context_config.get("chars_per_token_approx", 4))

        # Server settings
        server_config = config_data.get("server", {})
        self.server_host: str = os.getenv("SERVER_HOST") or server_config.get("host", "0.0.0.0")
        self.server_port: int = int(os.getenv("SERVER_PORT") or server_config.get("port", 8001))
        self.ssl_keyfile: Optional[str] = os.getenv("SSL_KEYFILE") or server_config.get("ssl_keyfile")
        self.ssl_certfile: Optional[str] = os.getenv("SSL_CERTFILE") or server_config.get("ssl_certfile")

        # Logging
        logging_config = config_data.get("logging", {})
        self.log_level: str = os.getenv("LOG_LEVEL") or logging_config.get("level", "INFO").upper()
        
        # Validate required settings
        if not self.jwt_secret:
            raise ValueError("JWT_SECRET is required. Set it in config.yaml under jwt.secret or as an environment variable.")

        # Nouvelle section pour l'authentification du dashboard
        self.dashboard_auth_enabled: bool = config_data.get("dashboard", {}).get("auth", {}).get("enabled", False)
        self.dashboard_username: str = config_data.get("dashboard", {}).get("auth", {}).get("username", "admin")
        self.dashboard_password: str = config_data.get("dashboard", {}).get("auth", {}).get("password", "admin")
        self.dashboard_session_expire_minutes: int = int(config_data.get("dashboard", {}).get("auth", {}).get("session_expire_minutes", 60))

    def __repr__(self) -> str:
        return f"<Settings(jwt_secret='****', rate_limit='{self.rate_limit}', port={self.server_port})>"

def load_config_data(file_path: str) -> Dict[str, Any]:
    """Loads configuration from a YAML file."""
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            try:
                return yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                print(f"Error parsing YAML file {file_path}: {e}")
                return {}
    return {}

# Load configuration data when the module is imported
_config_data = load_config_data(CONFIG_FILE_PATH)
settings = Settings(_config_data)


"""
# Example usage (can be removed or kept for testing):
if __name__ == "__main__":
    print(f"Loaded settings from '{CONFIG_FILE_PATH}' (with env overrides):")
    print(f"  JWT Secret: {'SET' if settings.jwt_secret else 'NOT SET'}")
    print(f"  JWT Algorithm: {settings.jwt_algorithm}")
    print(f"  JWT Expiration (min): {settings.jwt_expiration_minutes}")
    print(f"  Rate Limit: {settings.rate_limit}")
    print(f"  Max Tokens/Request: {settings.max_token_per_request}")
    print(f"  Chars per Token: {settings.chars_per_token_approx}")
    print(f"  Server Host: {settings.server_host}")
    print(f"  Server Port: {settings.server_port}")
    print(f"  SSL Keyfile: {settings.ssl_keyfile}")
    print(f"  SSL Certfile: {settings.ssl_certfile}")
    print(f"  Log Level: {settings.log_level}") 
"""