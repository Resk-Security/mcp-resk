import pytest
import json
import jsonschema
from pydantic import BaseModel
from resk_mcp.schema_validation import (
    SchemaValidationError,
    ToolSchemaValidator,
    tool_validator,
    generate_schema_from_model
)

# Test schemas
VALID_SCHEMA = {
    "type": "object",
    "properties": {
        "a": {"type": "integer"},
        "b": {"type": "string"}
    },
    "required": ["a"]
}

INVALID_SCHEMA = {
    "type": "invalid_type",  # Invalid schema type
    "properties": {
        "a": {"type": "integer"}
    }
}


@pytest.fixture
def validator():
    """Create a fresh ToolSchemaValidator instance for testing."""
    return ToolSchemaValidator()


def test_register_valid_schema(validator):
    """Test registering a valid schema."""
    validator.register_schema("test_tool", VALID_SCHEMA)
    assert "test_tool" in validator.tool_schemas
    assert validator.tool_schemas["test_tool"] == VALID_SCHEMA


def test_register_invalid_schema(validator):
    """Test registering an invalid schema raises an error."""
    with pytest.raises(ValueError):
        validator.register_schema("invalid_tool", INVALID_SCHEMA)


def test_validate_parameters_success(validator):
    """Test validating parameters against a schema successfully."""
    validator.register_schema("test_tool", VALID_SCHEMA)
    params = {"a": 1, "b": "test"}
    result = validator.validate_parameters("test_tool", params)
    assert result == params


def test_validate_parameters_failure(validator):
    """Test validating parameters that fail schema validation."""
    validator.register_schema("test_tool", VALID_SCHEMA)
    params = {"a": "not_an_integer", "b": "test"}  # 'a' should be an integer
    with pytest.raises(SchemaValidationError) as exc_info:
        validator.validate_parameters("test_tool", params)
    
    assert "test_tool" in str(exc_info.value)
    assert exc_info.value.errors


def test_validate_parameters_missing_required(validator):
    """Test validating parameters with missing required fields."""
    validator.register_schema("test_tool", VALID_SCHEMA)
    params = {"b": "test"}  # Missing required 'a'
    with pytest.raises(SchemaValidationError) as exc_info:
        validator.validate_parameters("test_tool", params)
    
    assert "test_tool" in str(exc_info.value)
    assert exc_info.value.errors


def test_validate_parameters_no_schema(validator):
    """Test validating parameters for a tool with no registered schema."""
    params = {"a": 1, "b": "test"}
    result = validator.validate_parameters("unknown_tool", params)
    assert result == params  # Should return params as-is without validation


class PydanticModelForTest(BaseModel):
    """Test Pydantic model for testing schema generation."""
    name: str
    age: int
    email: str | None = None


def test_generate_schema_from_model():
    """Test generating a JSON schema from a Pydantic model."""
    schema = generate_schema_from_model(PydanticModelForTest)
    
    assert schema["type"] == "object"
    assert "properties" in schema
    assert "name" in schema["properties"]
    assert "age" in schema["properties"]
    assert "email" in schema["properties"]
    assert "required" in schema
    assert "name" in schema["required"]
    assert "age" in schema["required"]
    assert "email" not in schema["required"]


def test_singleton_tool_validator():
    """Test that the singleton tool_validator instance works."""
    # Register a schema
    tool_validator.register_schema("singleton_test", VALID_SCHEMA)
    assert "singleton_test" in tool_validator.tool_schemas
    
    # Test validation
    params = {"a": 10}
    result = tool_validator.validate_parameters("singleton_test", params)
    assert result == params


def test_from_decorator_method(validator):
    """Test the from_decorator method creates a proper decorator."""
    # Define a mock async function
    async def mock_tool(a: int, b: str):
        return a, b
    
    # Apply decorator
    decorated = validator.from_decorator(VALID_SCHEMA)(mock_tool)
    
    # Check that schema was registered
    assert "mock_tool" in validator.tool_schemas
    assert validator.tool_schemas["mock_tool"] == VALID_SCHEMA 


# Integration tests with MCP server
@pytest.mark.asyncio
async def test_schema_validation_with_mcp_server():
    """Test schema validation integration with MCP server."""
    from resk_mcp.server import SecureMCPServer
    
    # Create a test server
    server = SecureMCPServer(name="TestSchemaServer")
    
    # Register schema for a test tool
    schema = {
        "type": "object",
        "properties": {
            "x": {"type": "number"},
            "y": {"type": "number"}
        },
        "required": ["x", "y"]
    }
    tool_validator.register_schema("math/multiply", schema)
    
    # Define a tool that will use the schema
    @server.tool(name="math/multiply")
    async def multiply(x: float, y: float) -> float:
        """Multiply two numbers."""
        return x * y
    
    # Test valid parameters
    valid_params = {"x": 5, "y": 3}
    validated_params = tool_validator.validate_parameters("math/multiply", valid_params)
    assert validated_params == valid_params
    
    # Test invalid parameters
    invalid_params = {"x": 5}  # Missing required 'y'
    with pytest.raises(SchemaValidationError):
        tool_validator.validate_parameters("math/multiply", invalid_params)


@pytest.mark.asyncio
async def test_decorator_integration():
    """Test the schema validation decorator with MCP server."""
    from resk_mcp.server import SecureMCPServer
    
    # Create a test server
    server = SecureMCPServer(name="TestDecoratorServer")
    
    # Define a tool with schema validation
    DIVIDE_SCHEMA = {
        "type": "object",
        "properties": {
            "dividend": {"type": "number"},
            "divisor": {"type": "number", "not": {"enum": [0]}}  # Prevent division by zero
        },
        "required": ["dividend", "divisor"]
    }
    
    @server.tool(name="math/divide")
    @tool_validator.from_decorator(DIVIDE_SCHEMA)
    async def divide(dividend: float, divisor: float) -> float:
        """Divide two numbers."""
        return dividend / divisor
    
    # Verify that the schema was registered
    assert "divide" in tool_validator.tool_schemas
    
    # Test valid parameters
    valid_params = {"dividend": 10, "divisor": 2}
    validated_params = tool_validator.validate_parameters("divide", valid_params)
    assert validated_params == valid_params
    
    # Test division by zero (should be caught by schema validation)
    invalid_params = {"dividend": 10, "divisor": 0}
    with pytest.raises(SchemaValidationError):
        tool_validator.validate_parameters("divide", invalid_params)


def test_pydantic_model_integration():
    """Test integration with Pydantic models for schema generation."""
    # Define a Pydantic model for parameters
    class UserData(BaseModel):
        username: str
        age: int
        is_active: bool = True
    
    # Generate a schema from the model
    user_schema = generate_schema_from_model(UserData)
    
    # Register the schema
    validator = ToolSchemaValidator()
    validator.register_schema("user/create", user_schema)
    
    # Test validation with the schema
    valid_user = {"username": "testuser", "age": 30}
    result = validator.validate_parameters("user/create", valid_user)
    assert result == valid_user
    
    # Test validation failure
    invalid_user = {"username": "testuser", "age": "thirty"}  # age should be int
    with pytest.raises(SchemaValidationError):
        validator.validate_parameters("user/create", invalid_user) 