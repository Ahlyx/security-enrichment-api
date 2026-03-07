import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from app.config import settings

DB_PATH = "cache.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_cache():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def make_key(query_type: str, value: str) -> str:
    raw = f"{query_type}:{value.lower().strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()

def get_cached(query_type: str, value: str) -> dict | None:
    key = make_key(query_type, value)
    conn = get_db()
    row = conn.execute(
        "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
    ).fetchone()
    conn.close()

    if not row:
        return None

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        delete_cached(query_type, value)
        return None

    return json.loads(row["value"])

def set_cached(query_type: str, value: str, data: dict):
    key = make_key(query_type, value)
    now = datetime.now(timezone.utc)
    expires_at = datetime.fromtimestamp(
        now.timestamp() + settings.cache_ttl_seconds, tz=timezone.utc
    )
    conn = get_db()
    conn.execute(
        """INSERT OR REPLACE INTO cache (key, value, created_at, expires_at)
           VALUES (?, ?, ?, ?)""",
        (key, json.dumps(data, default=str), now.isoformat(), expires_at.isoformat())
    )
    conn.commit()
    conn.close()

def delete_cached(query_type: str, value: str):
    key = make_key(query_type, value)
    conn = get_db()
    conn.execute("DELETE FROM cache WHERE key = ?", (key,))
    conn.commit()
    conn.close()