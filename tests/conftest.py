# tests/conftest.py
import os
import pytest
from unittest.mock import patch

# Import the auth module to monkeypatch
import resk_mcp.auth
from resk_mcp.auth import AuthError

# Set this to disable auth checking for tests
os.environ["BYPASS_AUTH_FOR_TESTS"] = "true"

# Create a mock verification function
def mock_verify_jwt_token(token, *args, **kwargs):
    """Mock function that always succeeds for test tokens."""
    print(f"MOCK JWT VERIFICATION: {token[:20] if token else 'None'}")
    # Return a valid payload with a test user ID
    return {"user_id": "test_user@example.com", "exp": 2147483647}

# This ensures the conftest.py is loaded first, enabling global settings
@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up the test environment with authentication bypass enabled."""
    original_env = {}
    # Store original environment variables
    for key in ["BYPASS_AUTH_FOR_TESTS"]:
        if key in os.environ:
            original_env[key] = os.environ[key]
        
    # Set test environment variables
    os.environ["BYPASS_AUTH_FOR_TESTS"] = "true"
    
    yield
    
    # Restore original environment
    for key, value in original_env.items():
        os.environ[key] = value 

@pytest.fixture(scope="session", autouse=True)
def patch_jwt_verification():
    """Patch the JWT verification function to always succeed in tests."""
    print("\nPATCHING JWT VERIFICATION GLOBALLY")
    
    # Save the original function
    original_func = resk_mcp.auth.verify_jwt_token
    
    # Replace with our mock function
    resk_mcp.auth.verify_jwt_token = mock_verify_jwt_token
    
    # Yield control back to tests
    yield
    
    # Restore the original function
    resk_mcp.auth.verify_jwt_token = original_func
    print("RESTORED ORIGINAL JWT VERIFICATION") 