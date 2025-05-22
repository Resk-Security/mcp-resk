# tests/conftest.py
import os
import pytest
from unittest.mock import patch

# Import the auth module to monkeypatch
import resk_mcp.auth
from resk_mcp.auth import AuthError

# This ensures the conftest.py is loaded first, enabling global settings
@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up the test environment if needed (placeholder for now)."""
    # Example: os.environ["SOME_SETTING"] = "test_value"
    yield
    # Example: del os.environ["SOME_SETTING"] 