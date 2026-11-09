"""
SQLite persistence management for Explainable-Adaptive-IDS.
Enforces WAL mode, handles table creation, parameterized queries, and safe retention.
"""
import sqlite3
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any

# Default database path inside project workspace
DEFAULT_DB_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "ids_local.db"


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Create a configured SQLite connection with WAL mode enabled."""
    target_path = db_path or DEFAULT_DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(target_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def initialize_database(db_path: Optional[Path] = None) -> None:
    """Initialize required database tables and indexes."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Events & Alert records
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                flow_duration REAL DEFAULT 0.0,
                packet_count INTEGER DEFAULT 0,
                byte_count INTEGER DEFAULT 0,
                is_malicious INTEGER NOT NULL,
                attack_category TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                severity TEXT NOT NULL,
                explanation_json TEXT,
                features_json TEXT,
                mode TEXT NOT NULL DEFAULT 'demo'
            );
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_is_malicious ON events(is_malicious);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_category ON events(attack_category);")
        
        # Concept Drift tracking logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS drift_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                feature_name TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                threshold REAL NOT NULL,
                drift_detected INTEGER NOT NULL,
                sample_size INTEGER NOT NULL,
                interpretation TEXT
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_drift_timestamp ON drift_logs(timestamp);")
        
        # Model adaptation & version registry
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS model_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT UNIQUE NOT NULL,
                model_type TEXT NOT NULL,
                trained_at TEXT NOT NULL,
                accuracy REAL,
                precision REAL,
                recall REAL,
                f1_score REAL,
                is_active INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT
            );
        """)
        
        # Settings key-value store
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        
        conn.commit()


def get_event_counts(db_path: Optional[Path] = None) -> Dict[str, int]:
    """Retrieve aggregate counts of processed flows and alerts."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM events;")
        total = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as malicious FROM events WHERE is_malicious = 1;")
        malicious = cursor.fetchone()["malicious"]
        
        normal = total - malicious
        return {"total": total, "normal": normal, "malicious": malicious}


def insert_event(event_data: Dict[str, Any], db_path: Optional[Path] = None) -> int:
    """Insert a single classified flow event into database."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO events (
                timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                flow_duration, packet_count, byte_count, is_malicious,
                attack_category, confidence_score, severity, explanation_json,
                features_json, mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_data.get("timestamp"),
            event_data.get("src_ip", "0.0.0.0"),
            event_data.get("dst_ip", "0.0.0.0"),
            event_data.get("src_port", 0),
            event_data.get("dst_port", 0),
            event_data.get("protocol", "TCP"),
            event_data.get("flow_duration", 0.0),
            event_data.get("packet_count", 0),
            event_data.get("byte_count", 0),
            1 if event_data.get("is_malicious") else 0,
            event_data.get("attack_category", "Normal"),
            event_data.get("confidence_score", 0.0),
            event_data.get("severity", "Informational"),
            json.dumps(event_data.get("explanation", {})),
            json.dumps(event_data.get("features", {})),
            event_data.get("mode", "demo")
        ))
        conn.commit()
        return cursor.lastrowid
