# resk_mcp/server.py
import logging
import os # Keep for specific os-level ops if any, but not for getenv for these settings
from typing import Dict, Any, Callable, Tuple, Optional, List

# from dotenv import load_dotenv # Handled by config.py now
from fastapi import FastAPI, HTTPException, Depends, Request as FastAPIRequest
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ValidationError as PydanticValidationError, field_validator
from starlette.requests import Request as StarletteRequest # For slowapi key func
from mcp.server.fastmcp import FastMCP
from mcp import types
from mcp.types import ToolAnnotations
from mcp.server import models

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Import the centralized settings object
from .config import settings
from .auth import verify_jwt_token, AuthError
from .validation import MCPRequestValidator, detect_pii, detect_prompt_injection, validate_request_payload
from .context import TokenBasedContextManager
from .dashboard import setup_dashboard_routes

# Custom MCP error codes
class MCPErrorCodes:
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    
    # Custom error codes
    AUTH_ERROR = -33000
    RATE_LIMIT_EXCEEDED = -33001
    CONTEXT_LIMIT_EXCEEDED = -33002
    SECURITY_VIOLATION = -33003
    UNIMPLEMENTED = -33004

# Custom MCP error response
class MCPErrorResponse(BaseModel):
    id: int
    error: Dict[str, Any]
    
    @classmethod
    def create(cls, request_id: int, code: int, message: str, data: Any = None):
        error = {"code": code, "message": message}
        if data:
            error["data"] = data
        return cls(id=request_id, error=error)

# load_dotenv() # Handled by config.py

# Logging configuration - now driven by settings
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)

# MAX_TOKEN_PER_REQUEST = int(os.getenv("MAX_TOKEN_PER_REQUEST", "4000")) # From settings
# RATE_LIMIT_DEFAULT = "100/minute" # From settings
# RATE_LIMIT_CONFIG = os.getenv("RATE_LIMIT", RATE_LIMIT_DEFAULT) # From settings

# Rate Limiter Key Function
def get_rate_limit_key(request: StarletteRequest) -> str:
    auth_header = request.headers.get("Authorization")
    token_str = None
    if auth_header and auth_header.startswith("Bearer "):
        token_str = auth_header.replace("Bearer ", "")
    
    if token_str:
        try:
            # verify_jwt_token will use settings for secret/algo by default
            payload = verify_jwt_token(token_str)
            user_id = payload.get("user_id")
            if user_id:
                return f"user:{user_id}"
            else:
                logger.warning("Token decoded for rate limiting but no user_id found. Falling back to IP.")
        except AuthError:
            logger.debug("AuthError during rate limit key extraction, falling back to IP.")
        except ValueError as ve: 
            logger.error(f"ValueError during rate limit key extraction (JWT secret likely not configured): {ve}. Falling back to IP.")
        except Exception as e:
            logger.error(f"Unexpected error decoding token for rate limiting: {e}. Falling back to IP.", exc_info=False)
    
    ip_address = get_remote_address(request)
    logger.debug(f"Rate limiting by IP address: {ip_address}")
    return f"ip:{ip_address}"

limiter = Limiter(key_func=get_rate_limit_key)

# Define a Pydantic model for the raw MCP request if needed for FastAPI path operation
# This is similar to your MCPRequest but can be used directly by FastAPI if you expose a direct POST
class RawMCPRequest(BaseModel):
    method: str
    params: Dict[str, Any]
    id: int # or str
    
    @field_validator('method')
    @classmethod
    def validate_method(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError('Method must be a non-empty string')
        
        allowed_prefixes = ['tool/', 'resource/', 'prompt/']
        if not any(v.startswith(prefix) for prefix in allowed_prefixes):
            raise ValueError(f'Method must start with one of: {", ".join(allowed_prefixes)}')
        
        return v
    
    @field_validator('params')
    @classmethod
    def validate_params(cls, v):
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError('Params must be an object')
        return v

class SecureMCPServer(FastMCP):
    def __init__(self, name: str = "SecureMCPServer", title: str = "Secure MCP Server", **kwargs):
        super().__init__(name=name, title=title, **kwargs)
        
        # Store title as an instance attribute
        self.title = title
        
        # In MCP v1.9.0, the FastMCP class structure has changed
        # Create a FastAPI app directly if the 'app' attribute doesn't exist
        from fastapi import FastAPI
        
        if hasattr(self, "app"):
            # Use the existing app from FastMCP if it exists
            self.secure_app = self.app
        else:
            # Create a new FastAPI app if MCP doesn't expose one
            self.secure_app = FastAPI(title=f"{title} API", description=f"Secure API for {name}")
            logger.info(f"Created new FastAPI app for {name} as MCP v1.9.0+ doesn't expose 'app' attribute")
            
        self.security_scheme = HTTPBearer()
        # Use settings for max_tokens
        self.context_manager = TokenBasedContextManager(max_tokens=settings.max_token_per_request)
        self.interactions: Dict[str, Dict[str, int]] = {"tools": {}, "resources": {}, "prompts": {}}
        
        # Store server start time for uptime calculations
        import time
        self.start_time = time.time()

        # Add storage for resources and prompts
        self._resources: Dict[str, Callable] = {}
        self._prompts: Dict[str, Callable] = {}

        # Setup rate limiter
        self.secure_app.state.limiter = limiter
        self.secure_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

        self._setup_secure_mcp_endpoint()
        setup_dashboard_routes(self.secure_app, self) # Pass this server instance

    def _get_mcp_handler(self) -> Callable:
        """
        Helper to get the original MCP request handler from FastMCP.
        
        Handles various MCP versions with different handler implementations.
        """
        logger.debug(f"Attempting to find MCP handler")

        try:
            # Check all possible handler methods in order of likelihood
            handler_methods = [
                "_dispatch",        # Used in MCP v1.9.0+
                "handle_request",   # Used in some MCP versions
                "process_request",  # Might be used in other implementations
                "dispatch"          # Common name for dispatch methods
            ]
            
            # Try each method in order
            for method_name in handler_methods:
                if hasattr(self, method_name) and callable(getattr(self, method_name)):
                    logger.info(f"Found MCP handler: self.{method_name}")
                    return getattr(self, method_name)
            
            # If we get here, try to implement a basic handler for core MCP functionality
            logger.warning("Could not find standard MCP request handler. Implementing basic handler.")
            
            async def basic_handler(request):
                """Basic MCP request handler implementation."""
                method = request.get("method", "")
                params = request.get("params", {})
                req_id = request.get("id", 0)
                
                # For tools, try to directly use the tools dictionary
                if method.startswith("tool/") and hasattr(self, "_tools"):
                    tool_name = method.split("tool/", 1)[1]
                    if tool_name in self._tools:
                        try:
                            tool_fn = self._tools[tool_name]
                            result = await tool_fn(**params)
                            return {"id": req_id, "result": result}
                        except Exception as e:
                            return {
                                "id": req_id,
                                "error": {
                                    "code": MCPErrorCodes.INTERNAL_ERROR,
                                    "message": f"Error executing tool: {str(e)}"
                                }
                            }
                
                # Default error response if we couldn't handle the request
                return {
                    "id": req_id,
                    "error": {
                        "code": MCPErrorCodes.METHOD_NOT_FOUND,
                        "message": f"Method {method} not found or not implemented in this basic handler"
                    }
                }
            
            return basic_handler
            
        except Exception as e:
            logger.error(f"Error finding MCP request handler: {e}", exc_info=True)
            raise RuntimeError(f"MCP request handler not found in FastMCP: {e}")

    def _setup_secure_mcp_endpoint(self):
        # Get the MCP handler from FastMCP
        original_mcp_dispatcher = self._get_mcp_handler()

        @self.secure_app.post("/mcp_secure", tags=["MCP"], description="Secure MCP Endpoint")
        @limiter.limit(settings.rate_limit) 
        async def handle_secure_mcp_request_http(
            request: FastAPIRequest,  # Required by SlowAPI rate limiter - renamed from fastapi_request 
            request_data: RawMCPRequest, 
            credentials: HTTPAuthorizationCredentials = Depends(self.security_scheme)
        ):
            user_id = "unknown_user"
            try:
                # Authenticate the request
                payload = verify_jwt_token(credentials.credentials)
                user_id = payload.get("user_id", "unknown_user")
                logger.info(f"Authenticated request for user: {user_id} via /mcp_secure")
            except AuthError as e:
                logger.warning(f"Authentication failed for /mcp_secure: {str(e)}")
                return MCPErrorResponse.create(
                    request_id=request_data.id,
                    code=MCPErrorCodes.AUTH_ERROR,
                    message=f"Invalid token: {str(e)}"
                )
            except ValueError as ve:
                logger.critical(f"JWT configuration error: {str(ve)}")
                return MCPErrorResponse.create(
                    request_id=request_data.id,
                    code=MCPErrorCodes.INTERNAL_ERROR,
                    message="Server authentication configuration error"
                )
            except Exception as e:
                logger.error(f"Unexpected auth error for /mcp_secure: {str(e)}")
                return MCPErrorResponse.create(
                    request_id=request_data.id,
                    code=MCPErrorCodes.AUTH_ERROR,
                    message="Authentication process failed"
                )

            try:
                # Extract and validate request parameters
                validated_mcp_request_params = request_data.params
                mcp_method_name = request_data.method
            except PydanticValidationError as e:
                logger.error(f"Validation error for /mcp_secure: {e}")
                return MCPErrorResponse.create(
                    request_id=request_data.id,
                    code=MCPErrorCodes.INVALID_REQUEST,
                    message=f"Invalid request payload: {str(e)}"
                )

            # Security checks
            try:
                # Check for prompt injection
                if detect_prompt_injection(validated_mcp_request_params):
                    logger.warning(f"Prompt injection detected for user {user_id} in /mcp_secure")
                    return MCPErrorResponse.create(
                            request_id=request_data.id,
                            code=MCPErrorCodes.SECURITY_VIOLATION,
                            message="Prompt injection detected"
                        )

                # Check for PII
                if detect_pii(validated_mcp_request_params):
                    logger.warning(f"Sensitive data (PII) detected for user {user_id} in /mcp_secure")
                    return MCPErrorResponse.create(
                            request_id=request_data.id,
                            code=MCPErrorCodes.SECURITY_VIOLATION,
                            message="Sensitive data (PII) detected"
                        )

                # Check context limits
                if not self.context_manager.is_within_limits(validated_mcp_request_params):
                    logger.warning(f"Context limit exceeded for user {user_id} in /mcp_secure")
                    return MCPErrorResponse.create(
                            request_id=request_data.id,
                            code=MCPErrorCodes.CONTEXT_LIMIT_EXCEEDED,
                            message="Context limit exceeded. Try a smaller request."
                        )
            except Exception as e:
                logger.error(f"Security check failed: {str(e)}")
                return MCPErrorResponse.create(
                    request_id=request_data.id,
                    code=MCPErrorCodes.INTERNAL_ERROR,
                    message="Security validation failed"
                )
            
            # Track interactions
            self._track_interaction(mcp_method_name)

            # Process the request based on method type
            try:
                return await self._process_mcp_method(
                    mcp_method_name, 
                    validated_mcp_request_params, 
                    request_data.id, 
                    user_id
                )
            except Exception as e:
                logger.error(f"Error executing MCP method {mcp_method_name} for user {user_id}: {str(e)}", exc_info=True)
                return MCPErrorResponse.create(
                    request_id=request_data.id,
                    code=MCPErrorCodes.INTERNAL_ERROR,
                    message=str(e)
                )

    async def _process_mcp_method(self, method_name: str, params: dict, request_id: int, user_id: str):
        """Process an MCP method call based on its type (tool, resource, or prompt)."""
        if method_name.startswith("tool/"):
            return await self._process_tool_method(method_name, params, request_id, user_id)
        elif method_name.startswith("resource/"):
            return await self._process_resource_method(method_name, params, request_id, user_id)
        elif method_name.startswith("prompt/"):
            return await self._process_prompt_method(method_name, params, request_id, user_id)
        else:
            logger.error(f"Unknown method type: {method_name}")
            return MCPErrorResponse.create(
                request_id=request_id,
                code=MCPErrorCodes.METHOD_NOT_FOUND,
                message=f"Unknown method type: {method_name}"
            )

    async def _process_tool_method(self, method_name: str, params: dict, request_id: int, user_id: str):
        """Process a tool method call."""
        # Extract the tool name without the "tool/" prefix
        tool_name = method_name.split("tool/", 1)[1] if method_name.startswith("tool/") else method_name
        
        logger.debug(f"Processing tool call: {tool_name}")

        try:
            # First try with the standard MCP call_tool interface
            if hasattr(self, "call_tool") and callable(self.call_tool):
                try:
                    # Try with the base tool name (without "tool/" prefix)
                    result = await self.call_tool(tool_name, params)
                    self._increment_tool_counter(tool_name, method_name)
                    return {"id": request_id, "result": result}
                except Exception as e:
                    # Log the error at debug level since we'll try other methods
                    logger.debug(f"call_tool failed with {tool_name}: {e}")
                    
                    # If first attempt failed, try with the full method name
                    try:
                        result = await self.call_tool(method_name, params)
                        self._increment_tool_counter(tool_name, method_name)
                        return {"id": request_id, "result": result}
                    except Exception as e2:
                        logger.debug(f"call_tool failed with {method_name}: {e2}")
                        # Continue to fallback mechanisms
            
            # Fallback: Try to find the tool in the _tool_manager (common in MCP 1.9.0+)
            if hasattr(self, "_tool_manager"):
                try:
                    tool = self._tool_manager.get_tool(tool_name)
                    if tool:
                        # The tool object is not callable directly in MCP 1.9.0+
                        # Call its execute method if available
                        if hasattr(tool, "execute") and callable(tool.execute):
                            result = await tool.execute(**params)
                        elif hasattr(tool, "call") and callable(tool.call):
                            result = await tool.call(**params)
                        elif hasattr(tool, "fn") and callable(tool.fn):
                            result = await tool.fn(**params)
                        else:
                            raise ValueError("Tool object found but doesn't have expected callable method")
                            
                        self._increment_tool_counter(tool_name, method_name)
                        return {"id": request_id, "result": result}
                except Exception as e:
                    logger.debug(f"Tool manager lookup failed: {e}")
            
            # If all approaches failed, report the tool as not found
            logger.error(f"Tool '{tool_name}' couldn't be executed: not found or execution failed")
            return MCPErrorResponse.create(
                request_id=request_id,
                code=MCPErrorCodes.METHOD_NOT_FOUND,
                message=f"Tool {tool_name} not found or couldn't be executed"
            )
        except TypeError as e:
            logger.error(f"Invalid parameters for tool {tool_name}: {str(e)}")
            return MCPErrorResponse.create(
                request_id=request_id,
                code=MCPErrorCodes.INVALID_PARAMS,
                message=f"Invalid parameters for tool {tool_name}: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {str(e)}")
            return MCPErrorResponse.create(
                request_id=request_id,
                code=MCPErrorCodes.INTERNAL_ERROR,
                message=f"Error executing tool {tool_name}: {str(e)}"
            )
    
    def _increment_tool_counter(self, tool_name: str, method_name: str):
        """Helper to increment the tool counter for successful executions."""
        # Try different name variants to find the right counter to increment
        for name_to_increment in [tool_name, f"tool/{tool_name}", method_name]:
            if name_to_increment in self.interactions["tools"]:
                self.interactions["tools"][name_to_increment] += 1
                break
    
    async def _process_resource_method(self, method_name: str, params: dict, request_id: int, user_id: str):
        """Process a resource method call."""
        resource_name = method_name.split("resource/", 1)[1]
        if hasattr(self, "resources") and resource_name in self.resources:
            logger.warning(f"Resource '{resource_name}' execution via POST /mcp_secure not fully implemented")
            return MCPErrorResponse.create(
                request_id=request_id,
                code=MCPErrorCodes.UNIMPLEMENTED,
                message=f"Resource {resource_name} execution via POST not implemented"
            )
        else:
            return MCPErrorResponse.create(
                request_id=request_id,
                code=MCPErrorCodes.METHOD_NOT_FOUND,
                message=f"Resource {resource_name} not found"
            )
    
    async def _process_prompt_method(self, method_name: str, params: dict, request_id: int, user_id: str):
        """Process a prompt method call."""
        prompt_name = method_name.split("prompt/", 1)[1]
        if hasattr(self, "prompts") and prompt_name in self.prompts:
            logger.warning(f"Prompt '{prompt_name}' execution via POST /mcp_secure not fully implemented")
            return MCPErrorResponse.create(
                request_id=request_id,
                code=MCPErrorCodes.UNIMPLEMENTED,
                message=f"Prompt {prompt_name} execution via POST not implemented"
            )
        else:
            return MCPErrorResponse.create(
                request_id=request_id,
                code=MCPErrorCodes.METHOD_NOT_FOUND,
                message=f"Prompt {prompt_name} not found"
            )

    def _track_interaction(self, mcp_method_name: str):
        parts = mcp_method_name.split("/", 1)
        if len(parts) == 2:
            element_type_plural = parts[0] + "s" # e.g. tool -> tools
            element_name = parts[1]
            if element_type_plural in self.interactions:
                if element_name not in self.interactions[element_type_plural]:
                    self.interactions[element_type_plural][element_name] = 0 # Initialize if new
                self.interactions[element_type_plural][element_name] += 1
                logger.debug(f"Tracked interaction for {element_type_plural}/{element_name}")
            else:
                logger.warning(f"Interaction tracking: Unknown element type in method name {mcp_method_name}")

    # Override FastMCP methods to track interactions
    def tool(self, name: str | None = None, description: str | None = None, annotations: Optional[ToolAnnotations] = None, **kwargs) -> Callable:
        """
        Register a tool function.
        
        Args:
            name: Name of the tool. If not provided, the function name will be used.
            description: Description of the tool. If not provided, the function docstring will be used.
            annotations: Tool annotations. 
            **kwargs: Additional parameters to pass to the function.
            
        Returns:
            Decorator to register a tool.
        """
        # Store the original tools dictionary before registration to identify new tools
        original_tools = {}
        if hasattr(self, "_tools") and isinstance(self._tools, dict):
            original_tools = self._tools.copy()
        
        decorator = super().tool(name, description=description, annotations=annotations, **kwargs)
        
        def actual_decorator(func: Callable) -> Callable:
            processed_func = decorator(func) # Let FastMCP process it first
            
            # Get the effective tool name
            tool_name_registered = name
            if not tool_name_registered:
                tool_name_registered = func.__name__
            
            # In MCP v1.9.0, tools might be registered with or without the "tool/" prefix
            # Try both versions in our interactions tracking
            self.interactions["tools"][tool_name_registered] = 0
            
            # Also track with "tool/" prefix if not already included
            if not tool_name_registered.startswith("tool/"):
                self.interactions["tools"][f"tool/{tool_name_registered}"] = 0
            
            logger.info(f"Registered secure tool: {tool_name_registered} for interaction tracking.")
            
            return processed_func
        return actual_decorator

    def resource(self, uri: Optional[str] = None, *, path_pattern: Optional[str] = None, name: str | None = None, description: str | None = None, mime_type: str | None = None, **kwargs) -> Callable:
        """
        Register a resource function.
        
        Args:
            uri: URI pattern for the resource.
            path_pattern: (Deprecated) Alias for uri parameter for backward compatibility.
            name: Name of the resource. If not provided, the function name will be used.
            description: Description of the resource. If not provided, the function docstring will be used.
            mime_type: MIME type of the resource.
            **kwargs: Additional parameters to pass to the function.
            
        Returns:
            Decorator to register a resource.
        """
        # Handle backward compatibility with path_pattern
        if uri is None and path_pattern is not None:
            uri = path_pattern
        elif uri is None and path_pattern is None:
            raise ValueError("Either 'uri' or 'path_pattern' must be provided")
        
        # At this point, uri cannot be None due to the checks above
        assert uri is not None, "URI cannot be None at this point"
            
        decorator = super().resource(uri, name=name, description=description, mime_type=mime_type, **kwargs)
        def actual_decorator(func: Callable) -> Callable:
            processed_func = decorator(func)
            # uri is the key FastMCP uses in self._resources
            self.interactions["resources"][uri] = 0
            logger.info(f"Registered secure resource: {uri} for interaction tracking.")
            return processed_func
        return actual_decorator

    def prompt(self, name: str | None = None, description: str | None = None, **kwargs) -> Callable:
        """
        Register a prompt function.
        
        Args:
            name: Name of the prompt. If not provided, the function name will be used.
            description: Description of the prompt. If not provided, the function docstring will be used.
            **kwargs: Additional parameters to pass to the function.
            
        Returns:
            Decorator to register a prompt.
        """
        decorator = super().prompt(name, description=description, **kwargs)
        def actual_decorator(func: Callable) -> Callable:
            processed_func = decorator(func)
            prompt_name_registered = name if name else func.__name__
            self.interactions["prompts"][prompt_name_registered] = 0
            logger.info(f"Registered secure prompt: {prompt_name_registered} for interaction tracking.")
            return processed_func
        return actual_decorator

    def get_interactions(self) -> Dict[str, Dict[str, int]]:
        return self.interactions

    def run_server(self, host=None, port=None, ssl_keyfile=None, ssl_certfile=None, **uvicorn_kwargs):
        """Start the secure server (potentially with HTTPS)."""
        import uvicorn
        from pathlib import Path
        
        # Use settings for defaults, but allow direct override from run_server call
        run_host = host if host is not None else settings.server_host
        run_port = port if port is not None else settings.server_port
        run_ssl_keyfile = ssl_keyfile if ssl_keyfile is not None else settings.ssl_keyfile
        run_ssl_certfile = ssl_certfile if ssl_certfile is not None else settings.ssl_certfile

        ssl_keyfile_path = Path(run_ssl_keyfile) if run_ssl_keyfile else None
        ssl_certfile_path = Path(run_ssl_certfile) if run_ssl_certfile else None

        if ssl_keyfile_path and ssl_certfile_path:
            if not ssl_keyfile_path.is_file():
                logger.error(f"SSL key file not found: {ssl_keyfile_path}")
                return
            if not ssl_certfile_path.is_file():
                logger.error(f"SSL cert file not found: {ssl_certfile_path}")
                return
            logger.info(f"Starting HTTPS server on {run_host}:{run_port}")
            uvicorn.run(
                self.secure_app, # Use the app with our security layers
                host=run_host,
                port=run_port,
                ssl_keyfile=str(ssl_keyfile_path),
                ssl_certfile=str(ssl_certfile_path),
                **uvicorn_kwargs
            )
        else:
            logger.info(f"Starting HTTP server on {run_host}:{run_port}. For HTTPS, provide SSL_KEYFILE and SSL_CERTFILE.")
            uvicorn.run(
                self.secure_app, 
                host=run_host, 
                port=run_port, 
                **uvicorn_kwargs
            )

# Example of how to run if this file is executed directly
if __name__ == "__main__":
    # Create a .env file in your project root with:
    # JWT_SECRET="your-super-secret-key-for-jwt"
    # SSL_KEYFILE="./key.pem"
    # SSL_CERTFILE="./cert.pem"
    # (Generate key.pem and cert.pem using openssl or mkcert)

    server = SecureMCPServer(name="MySecureAppFromConfig")

    @server.tool(name="calculator/add")
    async def add(a: int, b: int) -> int:
        """Adds two numbers."""
        logger.info(f"Tool 'add' called with a={a}, b={b}")
        return a + b

    @server.resource(uri="greeting/{name}")
    async def get_greeting(name: str) -> str:
        """Returns a personalized greeting."""
        return f"Hello, {name}! This is a secure resource."
    
    # To generate a test token:
    # from resk_mcp.auth import create_jwt_token
    # test_token = create_jwt_token(user_id="test_user@example.com")
    # print(f"Test token: {test_token}")

    # JWT_SECRET, SSL_KEYFILE, SSL_CERTFILE now come from settings object which loads .env/config.yaml
    # The run_server method will use these from settings by default.
    server.run_server()
    # To run without HTTPS:
    # server.run_server(port=8001)
    #
    # Then you can test with curl or httpie:
    # http POST http://localhost:8001/mcp_secure Authorization:"Bearer <your_token>" method="tool/calculator/add" params:='{"a": 5, "b": 7}' id:=1
    # For HTTPS:
    # http --verify=no POST https://localhost:8001/mcp_secure Authorization:"Bearer <your_token>" method="tool/calculator/add" params:='{"a": 5, "b": 7}' id:=1 

def main():
    """Entry point for the package, executed when run as `resk-mcp` command."""
    import argparse
    import logging
    
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Run the RESK MCP Secure Server")
    parser.add_argument("--host", help="Server host (default: from config)")
    parser.add_argument("--port", type=int, help="Server port (default: from config)")
    parser.add_argument("--ssl-key", help="SSL key file path (default: from config)")
    parser.add_argument("--ssl-cert", help="SSL certificate file path (default: from config)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                      help="Logging level (default: from config)")
    parser.add_argument("--jwt-secret", help="JWT secret key (default: from config)")
    parser.add_argument("--name", default="RESK-MCP-Server", help="Server name")
    args = parser.parse_args()
    
    # Configure logging
    if args.log_level:
        log_level = getattr(logging, args.log_level)
        logging.basicConfig(level=log_level)
    
    # Create and configure the server
    server = SecureMCPServer(name=args.name)
    
    # Register example tools
    @server.tool(name="calculator/add")
    async def add(a: int, b: int) -> int:
        """Adds two numbers."""
        logger.info(f"Tool 'add' called with a={a}, b={b}")
        return a + b

    @server.resource(uri="greeting/{name}")
    async def get_greeting(name: str) -> str:
        """Returns a personalized greeting."""
        return f"Hello, {name}! This is a secure resource."
    
    # Run the server with command-line args or config defaults
    server.run_server(
        host=args.host, 
        port=args.port,
        ssl_keyfile=args.ssl_key,
        ssl_certfile=args.ssl_cert,
        # If JWT secret was provided on command line, override it
        # Note: This approach requires patching the settings object after initialization
        # which may not be ideal; a better approach would be to pass this to the server
        # constructor if it accepts it.
    )
    
    if args.jwt_secret:
        from .config import settings
        settings.jwt_secret = args.jwt_secret
        logger.info("JWT secret overridden from command line")

if __name__ == "__main__":
    main() 