# tests/test_auth.py
import pytest
import time
from unittest.mock import patch
import jwt

from resk_mcp.auth import create_jwt_token, verify_jwt_token, AuthError
# Import settings to be able to mock it or its attributes
from resk_mcp import config as resk_mcp_config 

TEST_USER_ID = "test_user_123"
# These test-specific values can be used to override settings for specific tests
TEST_SECRET_KEY_OVERRIDE = "super-secret-test-key-override"
TEST_ALGORITHM_OVERRIDE = "HS512"
SHORT_EXP_SECONDS = 1

@pytest.fixture(autouse=True)
def mock_settings_for_auth_tests(monkeypatch):
    """Ensure default settings are predictable for most auth tests."""
    monkeypatch.setattr(resk_mcp_config.settings, 'jwt_secret', "default_test_secret_from_fixture")
    monkeypatch.setattr(resk_mcp_config.settings, 'jwt_algorithm', "HS256")
    monkeypatch.setattr(resk_mcp_config.settings, 'jwt_expiration_minutes', 30)

def test_create_and_verify_token():
    # Uses mocked default settings
    token = create_jwt_token(user_id=TEST_USER_ID)
    assert token is not None
    payload = verify_jwt_token(token)
    assert payload["user_id"] == TEST_USER_ID

def test_create_and_verify_token_with_overrides():
    # Test explicit overrides for create_jwt_token and verify_jwt_token args
    token = create_jwt_token(
        user_id=TEST_USER_ID, 
        secret_key=TEST_SECRET_KEY_OVERRIDE,
        algorithm=TEST_ALGORITHM_OVERRIDE,
        expires_delta_minutes=60
    )
    assert token is not None
    payload = verify_jwt_token(
        token, 
        secret_key=TEST_SECRET_KEY_OVERRIDE,
        algorithm=TEST_ALGORITHM_OVERRIDE
    )
    assert payload["user_id"] == TEST_USER_ID

def test_verify_tampered_token():
    token = create_jwt_token(user_id=TEST_USER_ID) # Uses mocked defaults
    tampered_token = token + "tamper"
    with pytest.raises(AuthError, match="Invalid token"):
        verify_jwt_token(tampered_token)

def test_verify_expired_token():
    expires_delta_minutes = SHORT_EXP_SECONDS / 60.0
    token = create_jwt_token(
        user_id=TEST_USER_ID, 
        expires_delta_minutes=expires_delta_minutes # Override expiration
    )
    time.sleep(SHORT_EXP_SECONDS + 0.5) 
    with pytest.raises(AuthError, match="Token has expired"):
        verify_jwt_token(token)

def test_verify_token_wrong_secret_override():
    # Create with mocked default secret
    token = create_jwt_token(user_id=TEST_USER_ID)
    # Attempt to verify with a different secret directly passed to verify_jwt_token
    with pytest.raises(AuthError, match="Invalid token"):
        verify_jwt_token(token, secret_key="another-secret-entirely")

def test_verify_token_different_algorithm_override():
    # Create with mocked default HS256
    token = create_jwt_token(user_id=TEST_USER_ID)
    # Attempt to verify with HS512 by overriding algorithm in verify_jwt_token
    with pytest.raises(AuthError, match="Invalid token"):
        verify_jwt_token(token, algorithm="HS512")


@patch.object(resk_mcp_config.settings, 'jwt_secret', None)
def test_create_token_no_configured_secret():
    with pytest.raises(ValueError, match="JWT secret key is not configured"):
        create_jwt_token(user_id=TEST_USER_ID)

@patch.object(resk_mcp_config.settings, 'jwt_secret', None)
def test_verify_token_no_configured_secret():
    # First, create a token with a temporary valid secret (not using the mocked None one)
    # because verify_jwt_token needs a token to try to verify.
    valid_temp_token = jwt.encode({"user_id": "temp"}, "temp_secret_for_this_test_only", algorithm="HS256")
    
    with pytest.raises(ValueError, match="JWT secret key is not configured for verification"):
        verify_jwt_token(valid_temp_token) 