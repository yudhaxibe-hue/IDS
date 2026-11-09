"""
Unit tests for SQLite database management and persistence.
"""
import pytest
from pathlib import Path
from backend.database.db import (
    get_db_connection,
    initialize_database,
    insert_event,
    get_event_counts
)


def test_database_initialization(tmp_path: Path):
    """Verify database tables and indexes are created with WAL mode."""
    test_db = tmp_path / "test_ids.db"
    initialize_database(test_db)

    with get_db_connection(test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        assert mode.upper() == "WAL"

        # Check required tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        assert "events" in tables
        assert "drift_logs" in tables
        assert "model_registry" in tables
        assert "settings" in tables


def test_insert_and_count_events(tmp_path: Path):
    """Verify flow event persistence and count aggregation."""
    test_db = tmp_path / "test_ids.db"
    initialize_database(test_db)

    initial_counts = get_event_counts(test_db)
    assert initial_counts["total"] == 0
    assert initial_counts["malicious"] == 0

    # Insert benign flow event
    insert_event({
        "timestamp": "2026-11-09T16:00:00",
        "src_ip": "192.168.1.5",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "is_malicious": False,
        "attack_category": "Normal",
        "confidence_score": 0.98,
        "severity": "Informational",
        "mode": "demo"
    }, db_path=test_db)

    # Insert malicious flow event
    insert_event({
        "timestamp": "2026-11-09T16:00:05",
        "src_ip": "10.0.0.99",
        "dst_ip": "192.168.1.1",
        "src_port": 44444,
        "dst_port": 80,
        "protocol": "TCP",
        "is_malicious": True,
        "attack_category": "DoS",
        "confidence_score": 0.92,
        "severity": "High",
        "mode": "demo"
    }, db_path=test_db)

    updated_counts = get_event_counts(test_db)
    assert updated_counts["total"] == 2
    assert updated_counts["normal"] == 1
    assert updated_counts["malicious"] == 1
