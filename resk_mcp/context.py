# resk_mcp/context.py
import json
from typing import Any, Dict

class TokenBasedContextManager:
    def __init__(self, max_tokens: int = 4000):
        """
        Initializes the context manager.
        Note: This is a simplified version. True token counting requires a tokenizer
        from a specific LLM (e.g., tiktoken for OpenAI models).
        This implementation approximates token count by character count or JSON string length.
        """
        self.max_tokens = max_tokens
        # Heuristic: average characters per token (can be adjusted)
        self.chars_per_token_approx = 4 

    def _estimate_tokens(self, data: Any) -> int:
        """Estimates the number of tokens in the given data."""
        if isinstance(data, (str, bytes)):
            return len(data) // self.chars_per_token_approx
        try:
            # For dicts, lists, etc., convert to JSON string and estimate
            json_str = json.dumps(data)
            return len(json_str) // self.chars_per_token_approx
        except (TypeError, OverflowError):
            # Fallback for un-serializable data, or very large numbers
            return len(str(data)) // self.chars_per_token_approx

    def is_within_limits(self, params: Dict[str, Any]) -> bool:
        """Checks if the estimated token count of the parameters is within limits."""
        estimated_tokens = self._estimate_tokens(params)
        # print(f"Estimated tokens: {estimated_tokens}") # For debugging
        return estimated_tokens <= self.max_tokens

    def get_remaining_tokens(self, current_params_tokens: int) -> int:
        """Calculates remaining tokens based on current usage."""
        return self.max_tokens - current_params_tokens 