import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "audit.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            operation TEXT,
            filename TEXT,
            file_hash TEXT,
            signer TEXT,
            key_size INTEGER,
            result TEXT,
            notes TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_operation(operation: str, filename: str, file_hash: str,
                  signer: str, key_size: int, result: str, notes: str = ""):
    conn = _get_conn()
    conn.execute(
        """INSERT INTO audit_log
           (timestamp, operation, filename, file_hash, signer, key_size, result, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (datetime.utcnow().isoformat(), operation, filename,
         file_hash, signer, key_size, result, notes),
    )
    conn.commit()
    conn.close()


def get_all_logs(limit: int = 200) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
