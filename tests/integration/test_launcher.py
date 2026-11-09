"""
Integration test for launcher port detection, background Uvicorn lifecycle, and clean termination.
"""
import urllib.request
import urllib.error
import pytest

from app.launcher import find_free_port, BackendServerThread, wait_for_server
from backend.api.auth import generate_session_token, set_session_token


def test_free_port_discovery():
    """Verify dynamic loopback port allocation."""
    p1 = find_free_port("127.0.0.1")
    p2 = find_free_port("127.0.0.1")
    assert isinstance(p1, int)
    assert 1024 < p1 <= 65535
    assert isinstance(p2, int)
    assert 1024 < p2 <= 65535


def test_launcher_backend_lifecycle():
    """Verify background server launches on loopback and stops cleanly."""
    host = "127.0.0.1"
    port = find_free_port(host)
    token = generate_session_token()
    set_session_token(token)

    server_thread = BackendServerThread(host, port)
    server_thread.start()

    try:
        # Check if local TCP socket connections are permitted in test environment
        ready = wait_for_server(host, port, timeout_sec=3.0)
        if not ready:
            # Check if this is due to sandbox socket restriction
            try:
                urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=1.0)
            except urllib.error.URLError as exc:
                if "Operation not permitted" in str(exc) or "Permission denied" in str(exc):
                    pytest.skip("Raw TCP loopback socket connections restricted by test sandbox environment")
            pytest.fail(f"Backend failed to respond on http://{host}:{port}/api/health")

        # Query health endpoint
        url = f"http://{host}:{port}/api/health"
        req = urllib.request.Request(url, headers={"X-Session-Token": token})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
    finally:
        # Stop server thread
        server_thread.stop()
