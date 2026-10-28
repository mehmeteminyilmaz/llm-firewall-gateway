import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

# Project root directory for consistent SQLite database file location
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = os.getenv("SQLITE_DB_PATH", str(BASE_DIR / "llmops.db"))


def init_db():
    """Veritabanını ve denetim log tablosunu (audit_logs) başlatır, eksik kolonları otomatik ekler."""
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
            total_tokens INTEGER,
            estimated_cost_usd REAL DEFAULT 0.0,
            pii_types TEXT DEFAULT '{}',
            model TEXT DEFAULT 'gpt-3.5-turbo'
        )
    ''')

    # Mevcut veritabanı tabloları için geriye dönük uyumlu kolon göçü (migration)
    cursor.execute("PRAGMA table_info(audit_logs)")
    existing_cols = {row[1] for row in cursor.fetchall()}

    if "estimated_cost_usd" not in existing_cols:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN estimated_cost_usd REAL DEFAULT 0.0")
    if "pii_types" not in existing_cols:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN pii_types TEXT DEFAULT '{}'")
    if "model" not in existing_cols:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN model TEXT DEFAULT 'gpt-3.5-turbo'")

    conn.commit()
    conn.close()


def log_request(
    status: str,
    threat_score: float,
    pii_count: int,
    gateway_latency: float,
    llm_latency: float,
    total_tokens: int,
    estimated_cost_usd: float = 0.0,
    pii_types: Optional[Dict[str, int]] = None,
    model: str = "gpt-3.5-turbo",
):
    """Her API isteğinin güvenlik, maliyet ve performans telemetrisini kaydeder."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    pii_types_json = json.dumps(pii_types or {}, ensure_ascii=False)
    cursor.execute(
        '''
        INSERT INTO audit_logs 
        (timestamp, status, threat_score, pii_count, gateway_latency_ms, llm_latency_ms, total_tokens, estimated_cost_usd, pii_types, model)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            datetime.now().isoformat(),
            status,
            threat_score,
            pii_count,
            gateway_latency,
            llm_latency,
            total_tokens,
            round(estimated_cost_usd, 6),
            pii_types_json,
            model or "gpt-3.5-turbo",
        ),
    )
    conn.commit()
    conn.close()


def get_db_path() -> str:
    """Aktif veritabanı dosya yolunu döner."""
    return DB_PATH
