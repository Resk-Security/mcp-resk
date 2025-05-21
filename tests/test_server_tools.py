"""
Tests for tool execution in the SecureMCPServer.
"""
import pytest
import asyncio
import json
from typing import Dict, Any
from unittest.mock import patch, MagicMock

from resk_mcp.server import SecureMCPServer, MCPErrorResponse
from resk_mcp.auth import create_jwt_token
from resk_mcp.config import settings

# Test data
TEST_USER_ID = "test_tools_user@example.com"
TEST_TOKEN = None  # Will be set in fixture


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


@pytest.fixture(scope="module")
def auth_token():
    """Create a JWT token for testing."""
    global TEST_TOKEN
    if not TEST_TOKEN:
        TEST_TOKEN = create_jwt_token(user_id=TEST_USER_ID)
    return TEST_TOKEN


@pytest.fixture(scope="module")
def server_instance():
    """Create a server instance with test tools."""
    server = SecureMCPServer(name="TestToolsServer")
    
    # Register a simple addition tool
    @server.tool(name="calculator/add")
    async def add(a: int, b: int) -> int:
        """Adds two numbers."""
        return a + b
    
    # Register a greeting tool with optional parameter
    @server.tool(name="greeting/hello")
    async def hello(name: str, language: str = "en") -> str:
        """Greets someone in the specified language."""
        greetings = {
            "en": f"Hello, {name}!",
            "fr": f"Bonjour, {name}!",
            "es": f"Hola, {name}!",
            "de": f"Hallo, {name}!"
        }
        return greetings.get(language, greetings["en"])
    
    # Register a tool that might raise exceptions
    @server.tool(name="math/divide")
    async def divide(a: float, b: float) -> float:
        """Divides a by b."""
        if b == 0:
            raise ValueError("Cannot divide by zero")
        return a / b
    
    return server


@pytest.mark.asyncio
async def test_add_tool_execution(server_instance):
    """Test the calculator/add tool executes correctly."""
    # Directly execute the tool via the MCP interface
    params = {"a": 5, "b": 3}
    result = await server_instance.call_tool("calculator/add", params)
    # Extract value from TextContent object if needed
    value = extract_value(result)
    assert value == "8" or int(value) == 8
    
    # Test with different parameters
    params = {"a": -2, "b": 10}
    result = await server_instance.call_tool("calculator/add", params)
    value = extract_value(result)
    assert value == "8" or int(value) == 8


@pytest.mark.asyncio
async def test_hello_tool_execution(server_instance):
    """Test the greeting/hello tool executes correctly with different parameters."""
    # Default language
    params = {"name": "Alice"}
    result = await server_instance.call_tool("greeting/hello", params)
    value = extract_value(result)
    assert value == "Hello, Alice!"
    
    # Specific language
    params = {"name": "Bob", "language": "fr"}
    result = await server_instance.call_tool("greeting/hello", params)
    value = extract_value(result)
    assert value == "Bonjour, Bob!"
    
    # Unknown language (should default to English)
    params = {"name": "Charlie", "language": "unknown"}
    result = await server_instance.call_tool("greeting/hello", params)
    value = extract_value(result)
    assert value == "Hello, Charlie!"


@pytest.mark.asyncio
async def test_tool_with_validation_errors(server_instance):
    """Test tool execution with invalid parameters."""
    # Missing required parameter
    params = {"a": 10}  # Missing 'b'
    with pytest.raises(Exception):  # The exact exception type depends on MCP implementation
        await server_instance.call_tool("calculator/add", params)
    
    # Wrong parameter type
    params = {"a": "not_a_number", "b": 5}
    with pytest.raises(Exception):
        await server_instance.call_tool("calculator/add", params)


@pytest.mark.asyncio
async def test_tool_business_logic_error(server_instance):
    """Test tool that raises a business logic error."""
    # Division by zero should raise an error
    params = {"a": 10, "b": 0}
    with pytest.raises(Exception):  # Now we expect any kind of exception from MCP
        await server_instance.call_tool("math/divide", params)
    
    # Valid division
    params = {"a": 10, "b": 2}
    result = await server_instance.call_tool("math/divide", params)
    value = extract_value(result)
    assert value == "5.0" or float(value) == 5.0


@pytest.mark.asyncio
async def test_nonexistent_tool(server_instance):
    """Test calling a tool that doesn't exist."""
    params = {"some": "params"}
    with pytest.raises(Exception):  # Exact exception depends on MCP implementation
        await server_instance.call_tool("nonexistent/tool", params)


@pytest.mark.asyncio
async def test_process_tool_method(server_instance):
    """Test the _process_tool_method directly."""
    # Test successful execution
    response = await server_instance._process_tool_method(
        "tool/calculator/add", 
        {"a": 3, "b": 4}, 
        request_id=1, 
        user_id=TEST_USER_ID
    )
    assert response["id"] == 1
    # Handle TextContent result object
    result_value = extract_value(response["result"])
    assert result_value == "7" or int(result_value) == 7
    
    # Test with error
    error_response = await server_instance._process_tool_method(
        "tool/nonexistent", 
        {}, 
        request_id=2, 
        user_id=TEST_USER_ID
    )
    
    # Check if it's an MCPErrorResponse object
    if isinstance(error_response, MCPErrorResponse):
        assert error_response.id == 2
        # Use model_dump() for Pydantic v2 compatibility
        if hasattr(error_response, 'model_dump'):
            assert "error" in error_response.model_dump()
        else:
            # Fallback for Pydantic v1
            assert "error" in error_response.dict()
    else:
        # If it's a dict (standard JSON-RPC error format)
        assert error_response["id"] == 2
        assert "error" in error_response


@pytest.mark.asyncio
async def test_tool_interaction_counter(server_instance):
    """Test that tool interaction counters increment correctly."""
    # Get initial counter value
    initial_add_count = server_instance.interactions["tools"].get("calculator/add", 0)
    
    # Execute the tool
    await server_instance.call_tool("calculator/add", {"a": 1, "b": 1})
    
    # Check that counter was incremented via the _process_tool_method call
    # We need to simulate the full MCP method call to increment the counter
    await server_instance._process_tool_method(
        "tool/calculator/add", 
        {"a": 1, "b": 2}, 
        request_id=99, 
        user_id=TEST_USER_ID
    )
    
    # Check that counter was incremented
    new_add_count = server_instance.interactions["tools"].get("calculator/add", 0)
    assert new_add_count > initial_add_count


@pytest.fixture
def mock_request():
    """Create a mock HTTP request with auth token."""
    class MockRequest:
        def __init__(self, token):
            self.headers = {"Authorization": f"Bearer {token}"}
    
    return MockRequest(TEST_TOKEN)


@pytest.mark.asyncio
async def test_mcp_secure_endpoint(server_instance, auth_token):
    """Test the /mcp_secure endpoint processes tool requests correctly."""
    from fastapi.testclient import TestClient
    from resk_mcp.server import RawMCPRequest
    
    client = TestClient(server_instance.secure_app)
    
    # Test successful request
    response = client.post(
        "/mcp_secure",
        json={
            "method": "tool/calculator/add",
            "params": {"a": 5, "b": 7},
            "id": 1
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1
    # Extract value from result
    result_value = extract_value(data["result"])
    assert result_value == "12" or int(result_value) == 12
    
    # Test request with invalid parameters
    response = client.post(
        "/mcp_secure",
        json={
            "method": "tool/calculator/add",
            "params": {"a": 5},  # Missing 'b'
            "id": 2
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    
    assert response.status_code == 200  # HTTP status is still 200 for JSON-RPC style errors
    data = response.json()
    assert data["id"] == 2
    assert "error" in data 