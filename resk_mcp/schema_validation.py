"""
Schema validation for MCP tool parameters.

This module provides functionality to validate parameters for MCP tools
against JSON schemas, ensuring proper type safety and valid input.
"""

import json
import logging
from typing import Any, Dict, Optional, List, Union, Callable
import jsonschema
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

class SchemaValidationError(Exception):
    """Exception raised when schema validation fails."""
    def __init__(self, message: str, errors: Optional[List[Dict[str, Any]]] = None):
        self.message = message
        self.errors = errors or []
        super().__init__(self.message)


class ToolSchemaValidator:
    """Validates MCP tool parameters against JSON schemas."""
    
    def __init__(self):
        self.tool_schemas: Dict[str, Dict[str, Any]] = {}
    
    def register_schema(self, tool_name: str, schema: Dict[str, Any]) -> None:
        """
        Register a JSON schema for a specific tool.
        
        Args:
            tool_name: Name of the tool
            schema: JSON schema for tool parameters
        """
        # Validate the schema itself to ensure it's a valid JSON schema
        try:
            # This validates that the schema conforms to the JSON Schema specification
            jsonschema.validators.validator_for(schema).check_schema(schema)
            self.tool_schemas[tool_name] = schema
            logger.info(f"Registered schema for tool: {tool_name}")
        except jsonschema.exceptions.SchemaError as e:
            logger.error(f"Invalid schema for tool {tool_name}: {e}")
            raise ValueError(f"Invalid JSON schema for tool {tool_name}: {e}")
    
    def validate_parameters(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate parameters against the registered schema for a tool.
        
        Args:
            tool_name: Name of the tool
            parameters: Parameters to validate
            
        Returns:
            The validated parameters (potentially modified for safety)
            
        Raises:
            SchemaValidationError: If validation fails
        """
        if tool_name not in self.tool_schemas:
            logger.warning(f"No schema registered for tool: {tool_name}")
            return parameters
        
        schema = self.tool_schemas[tool_name]
        
        try:
            jsonschema.validate(instance=parameters, schema=schema)
            return parameters
        except jsonschema.exceptions.ValidationError as e:
            errors = [{
                "path": ".".join(str(p) for p in e.path) if e.path else "",
                "message": e.message,
                "value": str(e.instance)
            }]
            logger.error(f"Validation failed for tool {tool_name}: {errors}")
            raise SchemaValidationError(
                f"Parameters for tool {tool_name} failed validation", 
                errors=errors
            )

    def from_decorator(self, schema: Dict[str, Any]) -> Callable:
        """
        Create a decorator to validate parameters against a schema.
        
        Args:
            schema: JSON schema for parameters
            
        Returns:
            A decorator function
        """
        def decorator(func: Callable) -> Callable:
            # Extract tool name from function
            tool_name = getattr(func, "__name__", "unknown_tool")
            
            # Register the schema
            self.register_schema(tool_name, schema)
            
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Validate kwargs against schema
                validated_kwargs = self.validate_parameters(tool_name, kwargs)
                return await func(*args, **validated_kwargs)
            
            return wrapper
        return decorator

# Create a singleton instance
tool_validator = ToolSchemaValidator()

# Helper function to generate a JSON schema from a pydantic model
def generate_schema_from_model(model_class: type) -> Dict[str, Any]:
    """
    Generate a JSON schema from a Pydantic model.
    
    Args:
        model_class: Pydantic model class
        
    Returns:
        JSON schema as a dictionary
    """
    # Check if this is a Pydantic model class
    if not issubclass(model_class, BaseModel):
        raise ValueError("Class must be a Pydantic model")
    
    # For Pydantic v2, use model_json_schema; for v1, use schema
    if hasattr(model_class, "model_json_schema"):
        return model_class.model_json_schema()
    elif hasattr(model_class, "schema"):
        return model_class.schema()
    else:
        raise ValueError("Unable to generate schema: Unsupported Pydantic version")


# Example usage in the server:
"""
# Example 1: Register a schema directly
CALCULATOR_SCHEMA = {
    "type": "object",
    "properties": {
        "a": {"type": "number"},
        "b": {"type": "number"}
    },
    "required": ["a", "b"]
}
tool_validator.register_schema("calculator/add", CALCULATOR_SCHEMA)

# Example 2: Use as a decorator with explicit schema
@server.tool(name="calculator/add")
@tool_validator.from_decorator(CALCULATOR_SCHEMA)
async def add(a: int, b: int) -> int:
    return a + b

# Example 3: Use with Pydantic model
class GreetingParams(BaseModel):
    name: str
    language: str = "en"
    
@server.tool(name="greeting/hello")
@tool_validator.from_decorator(generate_schema_from_model(GreetingParams))
async def hello(name: str, language: str = "en") -> str:
    return f"Hello {name}!" if language == "en" else f"Hola {name}!"
""" 