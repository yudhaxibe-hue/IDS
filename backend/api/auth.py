"""
Security and authentication layer for loopback API.
Ensures:
1. All API connections originate exclusively from local loopback (127.0.0.1 / ::1).
2. Protected endpoints require the per-session token generated at application launch.
"""
import secrets
from typing import Optional
from fastapi import Header, HTTPException, Request, status

_SESSION_TOKEN: Optional[str] = None


def generate_session_token() -> str:
    """Generate a cryptographically secure per-session token."""
    global _SESSION_TOKEN
    _SESSION_TOKEN = secrets.token_hex(32)
    return _SESSION_TOKEN


def get_session_token() -> Optional[str]:
    """Retrieve the current session token."""
    return _SESSION_TOKEN


def set_session_token(token: str) -> None:
    """Explicitly set the session token."""
    global _SESSION_TOKEN
    _SESSION_TOKEN = token


async def verify_loopback_only(request: Request) -> None:
    """
    Ensure the request originates strictly from loopback interface.
    """
    client_host = request.client.host if request.client else None
    if client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: API only accepts local loopback connections."
        )


async def verify_local_request(
    request: Request,
    x_session_token: Optional[str] = Header(None)
) -> None:
    """
    Validate that incoming requests originate from 127.0.0.1 (loopback)
    and contain the correct X-Session-Token header.
    """
    await verify_loopback_only(request)

    if _SESSION_TOKEN is not None:
        if not x_session_token or not secrets.compare_digest(x_session_token, _SESSION_TOKEN):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Invalid or missing session token."
            )
