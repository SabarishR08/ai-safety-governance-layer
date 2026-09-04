"""
database.py — SQLite helpers shared across the app.

Tables:
  events   — event stream (per-request scan records)
  policies — per-entity ALLOW/MASK/BLOCK rules, persisted in DB (inspired by sengan-s/techathon)
"""

import sqlite3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel_events.db")

# Default policies applied when no DB row exists for an entity
DEFAULT_POLICIES: Dict[str, str] = {
    "SSN":         "block",
    "Aadhaar":     "block",
    "Credit Card": "mask",
    "Email":       "mask",
    "Phone":       "mask",
    "API Key":     "block",
    "Gov ID":      "block",
    "IP Address":  "allow",
}


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_events_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                verdict     TEXT    NOT NULL,
                description TEXT    NOT NULL,
                agent_id    TEXT    NOT NULL,
                session_id  TEXT    NOT NULL,
                latency_ms  REAL    NOT NULL,
                risk_score  INTEGER NOT NULL,
                entities    TEXT    NOT NULL
            )
            """
        )
        # Policies table — key feature from sengan-s/techathon:
        # policies persist across restarts; frontend loads them on init
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policies (
                entity_type TEXT PRIMARY KEY,
                action      TEXT NOT NULL
            )
            """
        )
        # Seed defaults only if table is empty
        existing = conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
        if existing == 0:
            conn.executemany(
                "INSERT OR IGNORE INTO policies (entity_type, action) VALUES (?, ?)",
                list(DEFAULT_POLICIES.items()),
            )
        conn.commit()


def write_event(
    verdict: str,
    description: str,
    agent_id: str,
    session_id: str,
    latency_ms: float,
    risk_score: int,
    entities: list,
) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO events
                (timestamp, verdict, description, agent_id, session_id, latency_ms, risk_score, entities)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, verdict, description, agent_id, session_id, latency_ms, risk_score,
             json.dumps(entities)),
        )
        conn.commit()


def get_events(limit: int = 50) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["entities"] = json.loads(d["entities"])
        result.append(d)
    return result


# ── Policy helpers ────────────────────────────────────────────────────────────

def get_all_policies() -> Dict[str, str]:
    """Return {entity_type: action} for all policies."""
    with get_conn() as conn:
        rows = conn.execute("SELECT entity_type, action FROM policies").fetchall()
    return {r["entity_type"]: r["action"] for r in rows} if rows else dict(DEFAULT_POLICIES)


def upsert_policy(entity_type: str, action: str) -> None:
    """Create or update a policy row."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO policies (entity_type, action) VALUES (?, ?) "
            "ON CONFLICT(entity_type) DO UPDATE SET action=excluded.action",
            (entity_type, action),
        )
        conn.commit()
