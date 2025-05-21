# resk_mcp/auth.py
import jwt
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union
from .config import settings

# JWT_SECRET = os.getenv("JWT_SECRET", "your-default-secret-key") # Replaced by settings.jwt_secret
# JWT_ALGORITHM = "HS256" # Replaced by settings.jwt_algorithm
# JWT_EXPIRATION_MINUTES = 30 # Replaced by settings.jwt_expiration_minutes

class AuthError(Exception):
    pass

def create_jwt_token(user_id: str, 
                     secret_key: Optional[str] = None, # Allow override for testing, but default to config
                     algorithm: Optional[str] = None,
                     expires_delta_minutes: Optional[int] = None) -> str:
    """Creates a JWT token using centrally managed settings."""
    
    resolved_secret_key = secret_key if secret_key is not None else settings.jwt_secret
    resolved_algorithm = algorithm if algorithm is not None else settings.jwt_algorithm
    resolved_expires_delta_minutes = expires_delta_minutes if expires_delta_minutes is not None else settings.jwt_expiration_minutes

    if not resolved_secret_key:
        # This check is also in settings, but good for direct calls if settings weren't loaded properly.
        raise ValueError("JWT secret key is not configured.")
        
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=resolved_expires_delta_minutes)
    }
    token = jwt.encode(payload, resolved_secret_key, algorithm=resolved_algorithm)
    return token

def verify_jwt_token(token: str, 
                     secret_key: Optional[str] = None, # Allow override for testing
                     algorithm: Optional[str] = None) -> Dict[str, Any]:
    """Verifies a JWT token using centrally managed settings."""

    resolved_secret_key = secret_key if secret_key is not None else settings.jwt_secret
    # Use a list for algorithms as PyJWT expects
    algorithms_list = [algorithm if algorithm is not None else settings.jwt_algorithm]

    if not resolved_secret_key:
        raise ValueError("JWT secret key is not configured for verification.")

    try:
        payload = jwt.decode(token, resolved_secret_key, algorithms=algorithms_list)
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired")
    except jwt.InvalidTokenError as e:
        # Log the specific error for better debugging if needed, e.g. str(e)
        raise AuthError(f"Invalid token: {str(e)}") 