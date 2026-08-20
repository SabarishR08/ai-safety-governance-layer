"""
auditor.py — SHA-256 hash-chained audit log.

Every entry's hash = SHA-256(prev_hash + timestamp + agent_id + verdict + summary).
This makes the log tamper-evident: changing any entry breaks all subsequent hashes.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import List, Dict, Any


DB_PATH = "sentinel_audit.db"
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create audit table if it doesn't exist."""
    with _get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT    NOT NULL,
                agent_id      TEXT    NOT NULL,
                session_id    TEXT    NOT NULL,
                verdict       TEXT    NOT NULL,
                event_summary TEXT    NOT NULL,
                risk_score    INTEGER NOT NULL,
                audit_hash    TEXT    NOT NULL,
                prev_hash     TEXT    NOT NULL
            )
            """
        )
        conn.commit()


def _last_hash() -> str:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT audit_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return row["audit_hash"] if row else GENESIS_HASH


def _make_hash(prev: str, ts: str, agent: str, verdict: str, summary: str) -> str:
    payload = f"{prev}|{ts}|{agent}|{verdict}|{summary}"
    return hashlib.sha256(payload.encode()).hexdigest()


def write_entry(
    agent_id: str,
    session_id: str,
    verdict: str,
    event_summary: str,
    risk_score: int,
) -> str:
    """
    Append a new audit entry. Returns the hash of the new entry.
    """
    ts = datetime.now(timezone.utc).isoformat()
    prev = _last_hash()
    new_hash = _make_hash(prev, ts, agent_id, verdict, event_summary)

    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_log
                (timestamp, agent_id, session_id, verdict, event_summary, risk_score, audit_hash, prev_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, agent_id, session_id, verdict, event_summary, risk_score, new_hash, prev),
        )
        conn.commit()

    return new_hash


def get_entries(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent audit entries (newest first)."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> Dict[str, Any]:
    """Aggregate counts for the stats endpoint."""
    with _get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        masked = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE verdict='MASKED'"
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE verdict='BLOCKED'"
        ).fetchone()[0]
        avg_risk = conn.execute(
            "SELECT AVG(risk_score) FROM audit_log"
        ).fetchone()[0] or 0.0

    return {
        "total_scanned": total,
        "total_masked": masked,
        "total_blocked": blocked,
        "critical_exposures": blocked,
        "avg_risk_score": round(avg_risk, 1),
    }
