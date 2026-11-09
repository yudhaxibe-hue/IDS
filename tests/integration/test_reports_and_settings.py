"""
Integration tests for reports export (CSV/Summary) and application settings persistence.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from backend.api.auth import generate_session_token, set_session_token
from backend.database.db import insert_event


@pytest.fixture
def test_client():
    token = generate_session_token()
    set_session_token(token)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client, token
    # Teardown test artifacts
    from backend.database.db import get_db_connection
    with get_db_connection() as conn:
        conn.execute("DELETE FROM events WHERE src_ip = '10.0.0.50'")
        conn.commit()


def test_reports_csv_export(test_client):
    """Verify /api/reports/csv streams valid CSV content."""
    client, token = test_client

    # Insert a sample event
    insert_event({
        "timestamp": "2026-11-09T16:30:00Z",
        "src_ip": "10.0.0.50",
        "dst_ip": "192.168.1.1",
        "src_port": 44444,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 1500,
        "byte_count": 90000,
        "is_malicious": True,
        "attack_category": "DoS / DDoS",
        "confidence_score": 0.95,
        "severity": "High",
        "mode": "demo"
    })

    response = client.get("/api/reports/csv", headers={"X-Session-Token": token})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment; filename=ids_events_report.csv" in response.headers["content-disposition"]
    
    csv_text = response.text
    assert "Event ID" in csv_text
    assert "DoS / DDoS" in csv_text
    assert "10.0.0.50" in csv_text


def test_reports_summary_endpoint(test_client):
    """Verify /api/reports/summary returns aggregate metrics and category breakdown."""
    client, token = test_client
    response = client.get("/api/reports/summary", headers={"X-Session-Token": token})
    assert response.status_code == 200
    data = response.json()
    assert "total_flows_processed" in data
    assert "threat_alerts" in data
    assert "attack_breakdown" in data
    assert "active_model_version" in data


def test_settings_get_and_post(test_client):
    """Verify reading and updating settings in SQLite."""
    client, token = test_client

    # Read default settings
    get_resp = client.get("/api/settings", headers={"X-Session-Token": token})
    assert get_resp.status_code == 200
    assert "alert_threshold" in get_resp.json()

    # Update threshold to 0.85
    post_resp = client.post(
        "/api/settings",
        json={"alert_threshold": 0.85, "retention_days": 14},
        headers={"X-Session-Token": token}
    )
    assert post_resp.status_code == 200
    assert post_resp.json()["success"] is True

    # Verify updated settings
    get_resp2 = client.get("/api/settings", headers={"X-Session-Token": token})
    assert get_resp2.json()["alert_threshold"] == 0.85
    assert get_resp2.json()["retention_days"] == 14
