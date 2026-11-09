"""
Integration tests for FastAPI endpoints, lifecycle, and session token enforcement.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from backend.api.auth import generate_session_token, set_session_token


@pytest.fixture
def test_client():
    token = generate_session_token()
    set_session_token(token)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client, token


def test_api_rejection_without_token(test_client):
    """Verify endpoints reject unauthenticated requests with HTTP 403."""
    client, _ = test_client
    response = client.get("/api/status")
    assert response.status_code == 403
    assert "Invalid or missing session token" in response.json()["detail"]


def test_api_status_with_valid_token(test_client):
    """Verify /api/status succeeds with valid session token header."""
    client, token = test_client
    response = client.get("/api/status", headers={"X-Session-Token": token})
    assert response.status_code == 200
    data = response.json()
    assert "is_running" in data
    assert "monitoring_active" in data
    assert "counts" in data
    assert "platform" in data


def test_api_interfaces_endpoint(test_client):
    """Verify /api/interfaces returns adapter details and permission status."""
    client, token = test_client
    response = client.get("/api/interfaces", headers={"X-Session-Token": token})
    assert response.status_code == 200
    data = response.json()
    assert "interfaces" in data
    assert "capture_permissions" in data
    assert len(data["interfaces"]) > 0


def test_api_monitoring_start_stop_lifecycle(test_client):
    """Verify starting and stopping monitoring updates application state."""
    client, token = test_client

    # Start demo monitoring
    start_resp = client.post(
        "/api/monitoring/start",
        json={"mode": "demo", "interface": "demo_replay"},
        headers={"X-Session-Token": token}
    )
    assert start_resp.status_code == 200
    assert start_resp.json()["success"] is True

    # Check status reflects running
    status_resp = client.get("/api/status", headers={"X-Session-Token": token})
    assert status_resp.json()["monitoring_active"] is True
    assert status_resp.json()["monitoring_mode"] == "demo"

    # Stop monitoring
    stop_resp = client.post(
        "/api/monitoring/stop",
        headers={"X-Session-Token": token}
    )
    assert stop_resp.status_code == 200
    assert stop_resp.json()["success"] is True

    # Check status reflects idle
    status_resp2 = client.get("/api/status", headers={"X-Session-Token": token})
    assert status_resp2.json()["monitoring_active"] is False


def test_api_about_info(test_client):
    """Verify /api/about returns academic prototype metadata."""
    client, token = test_client
    response = client.get("/api/about", headers={"X-Session-Token": token})
    assert response.status_code == 200
    data = response.json()
    assert "Explainable Adaptive AI-Based Intrusion Detection System" in data["project_title"]
    assert "M.E." in data["academic_degree"]
