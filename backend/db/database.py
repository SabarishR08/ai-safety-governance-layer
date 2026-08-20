"""
database.py — SQLite helpers shared across the app.
The audit log uses its own connection in auditor.py;
this module handles event storage for the live stream endpoint.
"""

import sqlite3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

DB_PATH = "sentinel_events.db"


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
