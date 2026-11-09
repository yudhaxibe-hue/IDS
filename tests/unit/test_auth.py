"""
Unit tests for loopback authentication and session token verification.
"""
import asyncio
import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException

from backend.api.auth import (
    generate_session_token,
    get_session_token,
    set_session_token,
    verify_local_request
)


def test_session_token_generation():
    """Verify cryptographically random token generation."""
    t1 = generate_session_token()
    t2 = generate_session_token()
    assert len(t1) == 64
    assert len(t2) == 64
    assert t1 != t2
    assert get_session_token() == t2


def test_verify_local_request_success():
    """Verify loopback request passes with correct session token."""
    token = generate_session_token()
    mock_request = MagicMock()
    mock_request.client.host = "127.0.0.1"

    # Should not raise exception
    asyncio.run(verify_local_request(mock_request, x_session_token=token))


def test_verify_local_request_non_loopback_rejected():
    """Verify external non-loopback host is rejected with 403."""
    token = generate_session_token()
    mock_request = MagicMock()
    mock_request.client.host = "192.168.1.100"

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(verify_local_request(mock_request, x_session_token=token))
    assert exc_info.value.status_code == 403
    assert "loopback" in exc_info.value.detail


def test_verify_local_request_invalid_token_rejected():
    """Verify loopback host with invalid token is rejected with 403."""
    generate_session_token()
    mock_request = MagicMock()
    mock_request.client.host = "127.0.0.1"

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(verify_local_request(mock_request, x_session_token="invalid_token_123"))
    assert exc_info.value.status_code == 403
    assert "Invalid or missing session token" in exc_info.value.detail
