# resk_mcp/dashboard.py
from fastapi import APIRouter, Depends, FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Optional
import secrets
import time
from datetime import datetime, timedelta

# To avoid circular import with SecureMCPServer for type hinting
if TYPE_CHECKING:
    from .server import SecureMCPServer 

# Import settings for auth configuration
from .config import settings

router = APIRouter()

# Simple session store - in a production app, use a proper session backend
# Format: {"session_id": {"username": "user", "expires": timestamp}}
sessions = {}

# This is a bit of a workaround to pass the server instance to the route
# A more robust solution might involve FastAPI app state or dependency injection patterns
# For simplicity, we'll pass it during setup.

def setup_dashboard_routes(app: FastAPI, server_instance: 'SecureMCPServer'):
    base_path = Path(__file__).parent.parent # resk-mcp directoy, assuming static is a sibling
    static_files_path = base_path / "static"

    # Mount static files if the directory exists
    if static_files_path.exists() and static_files_path.is_dir():
        app.mount("/static", StaticFiles(directory=static_files_path), name="static")
    else:
        print(f"Warning: Static files directory not found at {static_files_path}")
        print(f"Current PWD for dashboard setup: {Path.cwd()}")
        print(f"Base path determined: {base_path}")

    # Login page
    @app.get("/", response_class=HTMLResponse)
    async def root():
        return RedirectResponse(url="/login")

    @app.get("/login", response_class=HTMLResponse)
    async def get_login_page(request: Request):
        # Check if user is already logged in
        session_id = request.cookies.get("session_id")
        if session_id and is_valid_session(session_id):
            return RedirectResponse(url="/dashboard")
            
        # Attempt to read the HTML file
        html_file_path = static_files_path / "login.html"
        if html_file_path.exists():
            with open(html_file_path, "r") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse("<html><body><h1>Login page not found.</h1></body></html>")

    @app.post("/api/dashboard/auth/login")
    async def login(request: Request):
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        
        # Check credentials
        if (not settings.dashboard_auth_enabled or 
            (username == settings.dashboard_username and password == settings.dashboard_password)):
            # Create session
            session_id = secrets.token_hex(16)
            expire_time = time.time() + (settings.dashboard_session_expire_minutes * 60)
            sessions[session_id] = {
                "username": username,
                "expires": expire_time
            }
            
            # Create response with session cookie
            response = JSONResponse(content={"success": True})
            response.set_cookie(
                key="session_id", 
                value=session_id,
                httponly=True,
                max_age=settings.dashboard_session_expire_minutes * 60,
                secure=True if settings.ssl_certfile else False,
                samesite="lax"
            )
            return response
        
        # Invalid credentials
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"success": False, "message": "Invalid credentials"}
        )

    @app.post("/api/dashboard/auth/logout")
    async def logout(request: Request):
        session_id = request.cookies.get("session_id")
        if session_id and session_id in sessions:
            del sessions[session_id]
        
        response = JSONResponse(content={"success": True})
        response.delete_cookie(key="session_id")
        return response

    # Authentication middleware function
    async def check_dashboard_auth(request: Request) -> Optional[Dict]:
        if not settings.dashboard_auth_enabled:
            return {"username": "anonymous"}
            
        session_id = request.cookies.get("session_id")
        if not session_id or not is_valid_session(session_id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return sessions[session_id]

    @app.get("/dashboard", response_class=HTMLResponse)
    async def get_dashboard_page(user_data: Dict = Depends(check_dashboard_auth)):
        # Attempt to read the HTML file relative to this dashboard.py file
        html_file_path = static_files_path / "dashboard.html"
        if html_file_path.exists():
            with open(html_file_path, "r") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse("<html><body><h1>Dashboard HTML not found.</h1></body></html>")

    @app.get("/api/dashboard/interactions")
    async def get_interaction_data(user_data: Dict = Depends(check_dashboard_auth)) -> Dict[str, Dict[str, int]]:
        return server_instance.get_interactions()
        
    @app.get("/api/dashboard/server-info")
    async def get_server_info(user_data: Dict = Depends(check_dashboard_auth)):
        # Get available tools, resources, and prompts in a sanitized format
        tools = [tool_name for tool_name in server_instance.interactions.get("tools", {})]
        resources = [resource_name for resource_name in server_instance.interactions.get("resources", {})]
        prompts = [prompt_name for prompt_name in server_instance.interactions.get("prompts", {})]
        
        # Calculate uptime in readable format
        import time
        current_time = time.time()
        uptime_seconds = int(current_time - getattr(server_instance, 'start_time', current_time))
        
        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        uptime_str = ""
        if days > 0:
            uptime_str += f"{days}d "
        if hours > 0 or days > 0:
            uptime_str += f"{hours}h "
        if minutes > 0 or hours > 0 or days > 0:
            uptime_str += f"{minutes}m "
        uptime_str += f"{seconds}s"
        
        # Get title from instance if available, otherwise use a default
        server_title = getattr(server_instance, 'title', "RESK-MCP Server")
        
        return {
            "server_name": server_instance.name,
            "server_title": server_title,
            "tools": tools,
            "resources": resources,
            "prompts": prompts,
            "uptime": uptime_str,
            "auth": {
                "method": "JWT" if settings.jwt_secret else "None",
                "expiration_minutes": settings.jwt_expiration_minutes
            },
            "rate_limit": settings.rate_limit
        }
        
def is_valid_session(session_id: str) -> bool:
    """Check if a session is valid and not expired"""
    if session_id not in sessions:
        return False
    
    session = sessions[session_id]
    if session["expires"] < time.time():
        # Expired session, clean it up
        del sessions[session_id]
        return False
        
    return True

def clean_expired_sessions():
    """Clean up expired sessions"""
    current_time = time.time()
    expired_sessions = [sid for sid, data in sessions.items() if data["expires"] < current_time]
    
    for session_id in expired_sessions:
        del sessions[session_id] 