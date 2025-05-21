# resk_mcp/validation.py
import re
from pydantic import BaseModel, validator, ValidationError as PydanticValidationError
from typing import Any, Dict, List

# Basic PII patterns (extend as needed)
PII_PATTERNS = {
    # Updated pattern for email with more precise matching
    "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    # Simplified phone number pattern to reduce false positives
    "PHONE": r"\b(?:\+?1[-\s.]?)?\(?\d{3}\)?[-\s.]?\d{3}[-\s.]?\d{4}\b",
    # Add more complex patterns for credit cards, SSNs, etc., carefully
}

# Basic prompt injection keywords (extend as needed)
PROMPT_INJECTION_KEYWORDS = [
    "ignore previous instructions",
    "disregard previous context",
    "act as though",
    "new context:",
    "system prompt:",
    "malicious input", # Example
]

class MCPRequestValidator(BaseModel):
    method: str
    params: Dict[str, Any]
    id: int # Or str, depending on MCP spec adherence

    @validator('params', pre=True, each_item=False)
    def check_params_structure(cls, v):
        if not isinstance(v, dict):
            raise ValueError("'params' must be a dictionary")
        return v

def validate_request_payload(data: Dict[str, Any]) -> MCPRequestValidator:
    try:
        return MCPRequestValidator(**data)
    except PydanticValidationError as e:
        # You might want to re-raise a custom error or log verbosely here
        raise e 

def _scan_for_patterns(text: str, patterns: List[str]) -> bool:
    """
    Scan text for regex patterns with improved error handling.
    Returns True if any pattern matches, False otherwise.
    """
    if not isinstance(text, str):
        return False
    
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        except re.error:
            # If regex pattern is invalid, log and continue
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Invalid regex pattern: {pattern}")
            continue
    return False

def detect_pii(data: Any) -> bool:
    """Recursively detects PII in nested data structures."""
    if isinstance(data, dict):
        # Skip param keys like "email" but check their values
        for key, value in data.items():
            # Only check the value, not the key name which might be a false positive
            if detect_pii(value):
                return True
    elif isinstance(data, list):
        for item in data:
            if detect_pii(item):
                return True
    elif isinstance(data, str):
        return _scan_for_patterns(data, list(PII_PATTERNS.values()))
    return False

def detect_prompt_injection(data: Any) -> bool:
    """Recursively detects prompt injection keywords in nested data structures."""
    if isinstance(data, dict):
        for key, value in data.items():
            if detect_prompt_injection(key) or detect_prompt_injection(value):
                return True
    elif isinstance(data, list):
        for item in data:
            if detect_prompt_injection(item):
                return True
    elif isinstance(data, str):
        return any(keyword.lower() in data.lower() for keyword in PROMPT_INJECTION_KEYWORDS)
    return False 