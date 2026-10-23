import sqlite3
from datetime import datetime
from pathlib import Path
import os

# Project root directory for consistent SQLite database file location
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = os.getenv("SQLITE_DB_PATH", str(BASE_DIR / "llmops.db"))


def init_db():
    """Veritabanını ve denetim log tablosunu (audit_logs) başlatır."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            status TEXT,
            threat_score REAL,
            pii_count INTEGER,
            gateway_latency_ms REAL,
            llm_latency_ms REAL,
            total_tokens INTEGER
        )
    ''')
    conn.commit()
    conn.close()


def log_request(status: str, threat_score: float, pii_count: int,
                gateway_latency: float, llm_latency: float, total_tokens: int):
    """Her API isteğinin güvenlik ve performans telemetrisini kaydeder."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs 
        (timestamp, status, threat_score, pii_count, gateway_latency_ms, llm_latency_ms, total_tokens)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (datetime.now().isoformat(), status, threat_score, pii_count, gateway_latency, llm_latency, total_tokens))
    conn.commit()
    conn.close()


def get_db_path() -> str:
    """Aktif veritabanı dosya yolunu döner."""
    return DB_PATH
