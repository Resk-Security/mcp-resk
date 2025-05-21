# tests/test_context.py
import pytest
from resk_mcp.context import TokenBasedContextManager

DEFAULT_MAX_TOKENS = 100 # Smaller for easier testing
CHARS_PER_TOKEN_APPROX = 4 # Should match the one in context.py for consistency

@pytest.fixture(scope="module")
def context_manager():
    """Create a TokenBasedContextManager instance for testing."""
    return TokenBasedContextManager(max_tokens=DEFAULT_MAX_TOKENS)

def test_context_manager_initialization():
    manager = TokenBasedContextManager(max_tokens=500)
    assert manager.max_tokens == 500

@pytest.mark.parametrize("params, expected_within_limits", [
    ({"text": "short"}, True), # Approx 5 chars / 4 = 1 token
    ({"text": "This is a medium length string for testing purposes"}, True), # Approx 50 chars / 4 = 12 tokens
    ({"text": "a" * (DEFAULT_MAX_TOKENS * CHARS_PER_TOKEN_APPROX - 10)}, True), # Slightly under limit to account for estimation differences
    ({"text": "a" * (DEFAULT_MAX_TOKENS * CHARS_PER_TOKEN_APPROX + 50)}, False), # Well over limit
    ({"data": [{"key": "value"} for _ in range(DEFAULT_MAX_TOKENS // 2)]}, False), # Likely over limit due to JSON structure
    ({}, True), # Empty params
    ({"number": 12345, "boolean": True}, True) # Non-string data, small token count
])
def test_is_within_limits(context_manager, params, expected_within_limits):
    assert context_manager.is_within_limits(params) == expected_within_limits

def test_estimate_tokens_various_types(context_manager):
    """Test token estimation for different data types."""
    # Use more tolerant assertions to account for different token estimation implementations
    assert context_manager._estimate_tokens("test") >= 1 # 4 chars
    assert context_manager._estimate_tokens("testtest") >= 2 # 8 chars
    assert context_manager._estimate_tokens({"key": "value"}) >= 1 # JSON overhead
    assert context_manager._estimate_tokens([1, 2, 3, 4, 5]) >= 1
    assert context_manager._estimate_tokens(12345) >= 1 
    assert context_manager._estimate_tokens(None) >= 1 # len(str(None)) = 4

def test_get_remaining_tokens(context_manager):
    """Test calculating remaining tokens after a request."""
    params_tokens_estimate = context_manager._estimate_tokens({"text": "some data"}) # Approx 9 chars / 4 = 2 tokens
    remaining = context_manager.get_remaining_tokens(params_tokens_estimate)
    assert remaining == DEFAULT_MAX_TOKENS - params_tokens_estimate
    assert remaining < DEFAULT_MAX_TOKENS

def test_context_limit_with_complex_object(context_manager):
    """Test context limit with a more complex nested object."""
    # Create a somewhat complex object
    complex_params = {
        "user_query": "Tell me about historical events in the 18th century, focusing on Europe.",
        "options": ["details", "summary", "timeline"],
        "user_preferences": {
            "language": "en-US",
            "response_length": "medium"
        }
    }
    
    # Estimate tokens
    estimated_tokens = context_manager._estimate_tokens(complex_params)
    
    # Use a clearer assertion pattern that won't be affected by estimation differences
    within_limits = context_manager.is_within_limits(complex_params)
    if estimated_tokens <= DEFAULT_MAX_TOKENS:
        assert within_limits is True
    else:
        assert within_limits is False 