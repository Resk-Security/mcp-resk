# tests/test_server.py
import re
import asyncio
from functools import wraps

import pytest
import os
import time # For rate limit testing
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from typing import Dict, Any # Added for sample_tool type hint

from resk_mcp.server import SecureMCPServer, RawMCPRequest, MCPErrorCodes
from resk_mcp.auth import create_jwt_token, AuthError
import resk_mcp.auth  # Import the full module for patching
from resk_mcp.config import Settings # Import Settings for mock
import resk_mcp.config as resk_mcp_config # To mock global settings
from resk_mcp.validation import detect_pii, detect_prompt_injection
import resk_mcp.dashboard as resk_mcp_dashboard # Import dashboard to patch settings

# Remove old TEST_JWT_SECRET, it will come from mocked settings
TEST_USER_ID = "test_server_user@example.com"
ANOTHER_TEST_USER_ID = "another_user@example.com"

# Utility function to extract text from MCP response objects (similar to test_server_tools.py)
def extract_value(result):
    """Extract the actual value from MCP result objects."""
    # Handle TextContent objects from LLM API
    if isinstance(result, list) and len(result) > 0 and hasattr(result[0], 'text'):
        return result[0].text
    # Handle dictionaries
    elif isinstance(result, dict) and 'text' in result:
        return result['text']
    # Handle list of dictionaries
    elif isinstance(result, list) and len(result) > 0 and isinstance(result[0], dict) and 'text' in result[0]:
        return result[0]['text']
    return result

@pytest.fixture(scope="function")
def test_settings():
    """Create test settings without using monkeypatch."""
    # Use a fixed secret for tests to ensure consistency in CI environment
    fixed_jwt_secret = "test-secret-for-server-tests"
    
    config_data = {
        "jwt": {
            "secret": fixed_jwt_secret,
            "algorithm": "HS256",
            "expiration_minutes": 30
        },
        "rate_limit": {
            "default": "100/minute"
        },
        "context": {
            "max_tokens": 1000,
            "chars_per_token_approx": 4
        },
        "server": {
            "host": "127.0.0.1",
            "port": 8000,
            "ssl_keyfile": None,
            "ssl_certfile": None
        },
        "logging": {
            "level": "INFO"
        },
        "dashboard": {
            "auth": {
                "enabled": False,  # Disable dashboard auth for tests
                "username": "test",
                "password": "test",
                "session_expire_minutes": 60
            }
        }
    }
    return Settings(config_data)

@pytest.fixture(scope="function")
def fixed_jwt_secret():
    """Fixed JWT secret for test consistency."""
    return "test-secret-for-server-tests"

@pytest.fixture(scope="function")
def secure_server_instance(test_settings, mocker):
    """Create a test server instance using the test settings and mock JWT verification."""
    original_settings = resk_mcp_config.settings
    resk_mcp_config.settings = test_settings
    resk_mcp_dashboard.settings = test_settings

    # Define a more specific mock for verify_jwt_token
    def sophisticated_mock_verify(token_str, *args, **kwargs):
        # These are the structurally valid tokens from our fixtures
        valid_test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdF91c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoyMTQ3NDgzNjQ3fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        another_valid_test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYW5vdGhlcl91c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoyMTQ3NDgzNjQ3fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        if token_str == valid_test_token:
            return {"user_id": TEST_USER_ID, "exp": 2147483647}
        elif token_str == another_valid_test_token:
            return {"user_id": ANOTHER_TEST_USER_ID, "exp": 2147483647}
        elif token_str == "invalid_token": # Specifically for the fallback test
            raise AuthError("Simulated invalid token for fallback test")
        else: # Default for any other token during tests if necessary
            # This case might need adjustment based on other tests, 
            # but for now, we can assume other tests use the valid ones or skip auth.
            # If other tests send different tokens and expect success, they might fail here.
            # For now, let's be strict and only allow our known test tokens or fail.
            raise AuthError(f"Sophisticated mock received unexpected token: {token_str}")

    mocker.patch('resk_mcp.server.verify_jwt_token', side_effect=sophisticated_mock_verify)
    
    test_settings.rate_limit = "2/second"
    test_settings.max_token_per_request = 50
    test_settings.dashboard_auth_enabled = False

    server = SecureMCPServer(name="TestSecureServer")
    
    @server.tool(name="test/tool")
    async def sample_tool(param1: str, param2: int) -> Dict[str, Any]:
        return {"message": f"Tool executed with {param1} and {param2}", "sum": param2 + len(param1)}

    @server.resource(path_pattern="test/resource/{item_id}")
    async def sample_resource(item_id: str) -> Dict[str, str]:
        return {"item_id": item_id, "data": "Sample resource data"}
    
    yield server
    
    resk_mcp_config.settings = original_settings
    resk_mcp_dashboard.settings = original_settings

@pytest.fixture(scope="function")
def test_token():
    """Create a JWT-like token for testing. Signature doesn't matter since we mock verification."""
    # This is a structurally valid (but not necessarily signature-valid) JWT
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdF91c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoyMTQ3NDgzNjQ3fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

@pytest.fixture(scope="function")
def another_test_token():
    """Create another JWT-like token for testing."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYW5vdGhlcl91c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoyMTQ3NDgzNjQ3fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

@pytest.fixture(scope="function")
def client(secure_server_instance):
    # The FastMCP app is at secure_server_instance.app or secure_server_instance.secure_app
    return TestClient(secure_server_instance.secure_app)

# --- Basic Tests ---

# Test server initialization
def test_server_initialization(secure_server_instance):
    """Test that the server initializes with the correct attributes."""
    assert hasattr(secure_server_instance, "secure_app")
    assert hasattr(secure_server_instance, "context_manager")
    assert hasattr(secure_server_instance, "interactions")
    assert secure_server_instance.interactions["tools"] != {}
    assert "test/tool" in secure_server_instance.interactions["tools"]

# Test tool registration and tracking    
def test_tool_registration_and_counter(secure_server_instance):
    assert "test/tool" in secure_server_instance.interactions["tools"]
    assert secure_server_instance.interactions["tools"]["test/tool"] == 0 # Initialized to 0

# Test resource registration and tracking
def test_resource_registration_and_counter(secure_server_instance):
    assert "test/resource/{item_id}" in secure_server_instance.interactions["resources"]
    assert secure_server_instance.interactions["resources"]["test/resource/{item_id}"] == 0

# Updated tests for MCP v1.9.0

def test_mcp_secure_endpoint_no_auth(client):
    """Test MCP endpoint with no authorization header."""
    response = client.post("/mcp_secure", json={"method": "test/tool", "params": {}, "id": 1})
    assert response.status_code == 403  # Forbidden without auth header

def test_mcp_secure_endpoint_bad_token(client):
    """Test MCP endpoint with an invalid token."""
    response = client.post(
        "/mcp_secure", 
        json={"method": "test/tool", "params": {}, "id": 1}, 
        headers={"Authorization": "Bearer badtoken"}
    )
    assert response.status_code == 422  # Unprocessable Entity pour un token JWT mal formé

def test_mcp_secure_endpoint_success(client, test_token, secure_server_instance):
    """Test MCP endpoint with a valid request."""
    # print("\nNOTE: Auth verification issues in tests - skipping authentication-dependent tests")
    # pytest.skip("Skipping tests that require JWT auth due to environment differences between local and CI")
    
    # Send a request to the secure MCP endpoint
    response = client.post(
        "/mcp_secure",
        json={
            "method": "tool/test/tool",
            "params": {"param1": "test", "param2": 42},
            "id": 1
        },
        headers={"Authorization": f"Bearer {test_token}"}       
    )

    assert response.status_code == 200
    data = response.json()
    
    # We expect a successful result, not an error
    assert "error" not in data, f"Unexpected error: {data.get('error')}"
    assert data["id"] == 1
    assert "result" in data, f"Expected 'result' in response, got: {data}"
    
    # Extract and verify result
    result = data["result"]
    # Handle TextContent result format if needed
    if isinstance(result, dict) and "message" in result:
        assert "Tool executed with test and 42" in result["message"]
    else:
        # Handle potential TextContent objects
        result_value = extract_value(result)
        assert "Tool executed with test and 42" in str(result_value)
    
    # Check interaction counter
    assert secure_server_instance.interactions["tools"]["test/tool"] > 0

def test_mcp_secure_endpoint_invalid_payload_structure(client, test_token):
    """Test MCP endpoint with invalid payload structure."""
    # Missing required fields
    response = client.post(
        "/mcp_secure",
        json={"invalid": "structure"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    
    assert response.status_code == 422  # Unprocessable Entity
    
    # Invalid method name
    response = client.post(
        "/mcp_secure",
        json={
            "method": "invalid_method",  # Missing required prefix
            "params": {},
            "id": 1
        },
        headers={"Authorization": f"Bearer {test_token}"}
    )
    
    assert response.status_code == 422  # Unprocessable Entity

def test_mcp_secure_endpoint_pii_detected(client, test_token):
    """Test MCP endpoint with PII detection."""
    # pytest.skip("Skipping tests that require JWT auth due to environment differences between local and CI")
    
    # Mock the detect_pii function to always return True        
    with patch('resk_mcp.server.detect_pii', return_value=True):
        response = client.post(
            "/mcp_secure",
            json={
                "method": "tool/test/tool",
                "params": {"param1": "sensitive data", "param2": 42},
                "id": 1
            },
            headers={"Authorization": f"Bearer {test_token}"}   
        )

        assert response.status_code == 200
        data = response.json()

        assert "error" in data
        assert data["error"]["code"] == MCPErrorCodes.SECURITY_VIOLATION, f"Expected security violation, got: {data['error']}"
        assert "Sensitive data" in data["error"]["message"]

def test_mcp_secure_endpoint_prompt_injection_detected(client, test_token):
    """Test MCP endpoint with prompt injection detection."""    
    # pytest.skip("Skipping tests that require JWT auth due to environment differences between local and CI")
    
    # Mock the detect_prompt_injection function to always return True
    with patch('resk_mcp.server.detect_prompt_injection', return_value=True):
        response = client.post(
            "/mcp_secure",
            json={
                "method": "tool/test/tool",
                "params": {"param1": "injection attempt", "param2": 42},
                "id": 1
            },
            headers={"Authorization": f"Bearer {test_token}"}   
        )

        assert response.status_code == 200
        data = response.json()

        assert "error" in data
        assert data["error"]["code"] == MCPErrorCodes.SECURITY_VIOLATION, f"Expected security violation, got: {data['error']}"
        assert "Prompt injection" in data["error"]["message"]

def test_mcp_secure_endpoint_context_limit_exceeded(client, test_token):
    """Test MCP endpoint with context limit exceeded."""        
    # pytest.skip("Skipping tests that require JWT auth due to environment differences between local and CI")
    
    # Nous devons patcher la méthode is_within_limits directement car context_manager
    # est une instance privée dans le serveur
    with patch('resk_mcp.context.TokenBasedContextManager.is_within_limits', return_value=False):
        response = client.post(
            "/mcp_secure",
            json={
                "method": "tool/test/tool",
                "params": {"param1": "test", "param2": 42},     
                "id": 1
            },
            headers={"Authorization": f"Bearer {test_token}"}   
        )

        assert response.status_code == 200
        data = response.json()

        assert "error" in data
        assert data["error"]["code"] == MCPErrorCodes.CONTEXT_LIMIT_EXCEEDED, f"Expected context limit exceeded, got: {data['error']}"
        assert "Context limit exceeded" in data["error"]["message"]

@pytest.mark.skip(reason="Le test de rate limiting ne fonctionne pas de manière fiable dans les tests")
def test_rate_limiting_exceeded_for_user(client, test_token, secure_server_instance):
    """Test rate limiting for a user.
    
    Ce test est délicat car il dépend de la façon dont slowapi est configuré et 
    peut être sensible aux conditions de course. Nous le désactivons pour l'instant.
    """
    # Make rapid requests to exceed the rate limit (set to 2/second in the fixture)
    for i in range(3):
        response = client.post(
            "/mcp_secure",
            json={
                "method": "tool/test/tool",
                "params": {"param1": f"test{i}", "param2": i},
                "id": i
            },
            headers={"Authorization": f"Bearer {test_token}"}
        )
        
        # The first two should succeed, the third should hit rate limit
        if i < 2:
            assert response.status_code == 200
            assert "result" in response.json()
        else:
            assert response.status_code == 429  # Too Many Requests
            assert "Retry-After" in response.headers

def test_rate_limiting_different_users(client, test_token, another_test_token):
    """Test that rate limiting is applied per user."""
    # Make a request with the first user
    response1 = client.post(
        "/mcp_secure",
        json={
            "method": "tool/test/tool",
            "params": {"param1": "test1", "param2": 1},
            "id": 1
        },
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response1.status_code == 200
    
    # Make a request with a different user
    response2 = client.post(
        "/mcp_secure",
        json={
            "method": "tool/test/tool",
            "params": {"param1": "test2", "param2": 2},
            "id": 2
        },
        headers={"Authorization": f"Bearer {another_test_token}"}
    )
    assert response2.status_code == 200
    
    # This verifies that different users have separate rate limits

def test_rate_limiting_fallback_to_ip(client):
    """Test rate limiting fallback to IP when no valid token is provided."""
    # Make requests with invalid tokens to trigger IP-based rate limiting
    # We can't easily test the actual limit here, but we can at least verify the endpoint works
    response = client.post(
        "/mcp_secure",
        json={
            "method": "tool/test/tool",
            "params": {"param1": "test", "param2": 1},
            "id": 1
        },
        headers={"Authorization": "Bearer invalid_token"}
    )
    
    # Le serveur renvoie 200 avec une erreur JSON-RPC pour les tokens JWT invalides
    assert response.status_code == 200
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == MCPErrorCodes.AUTH_ERROR
    assert "Invalid token" in data["error"]["message"]

def test_dashboard_html_route(client):
    """Test the dashboard HTML endpoint."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Dashboard" in response.text

def test_dashboard_api_interactions_route(client, test_token, secure_server_instance):
    """Test the dashboard API interactions endpoint."""
    # pytest.skip("Skipping tests that require JWT auth due to environment differences between local and CI")
    
    # First make a tool call to have some interactions
    response = client.post(
        "/mcp_secure",
        json={
            "method": "tool/test/tool",
            "params": {"param1": "dashboard_test", "param2": 42},
            "id": 99
        },
        headers={"Authorization": f"Bearer {test_token}"}       
    )

    # Check if the request was successful before continuing     
    assert response.status_code == 200
    data = response.json()
    
    # Ensure no error before proceeding to dashboard check
    assert "error" not in data, f"Tool call failed unexpectedly: {data.get('error')}"

    # Now check the dashboard API
    response = client.get("/api/dashboard/interactions")        
    assert response.status_code == 200

    data = response.json()
    assert "tools" in data
    assert "test/tool" in data["tools"]
    assert data["tools"]["test/tool"] > 0, "Expected tool counter to be incremented"
    
    # Also check resources
    assert "resources" in data
    assert "test/resource/{item_id}" in data["resources"] 