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


import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel_audit.db")
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


def verify_chain() -> Dict[str, Any]:
    """Verify the integrity of the SHA-256 hash chain and pinpoint any tampered block."""
    with _get_conn() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    
    if not rows:
        return {"valid": True, "total_blocks": 0, "message": "Genesis state: ledger is empty"}

    expected_prev = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "error_id": row["id"],
                "reason": f"Broken chain link at Block #{row['id']}: prev_hash pointer was corrupted!",
            }
        
        computed_hash = _make_hash(
            expected_prev, 
            row["timestamp"], 
            row["agent_id"], 
            row["verdict"], 
            row["event_summary"]
        )
        
        if computed_hash != row["audit_hash"]:
            return {
                "valid": False,
                "error_id": row["id"],
                "reason": f"Tampered entry detected at Block #{row['id']}: row payload was illegally altered!",
                "expected_hash": computed_hash[:10] + "…",
                "found_hash": row["audit_hash"][:10] + "…",
            }
            
        expected_prev = computed_hash
        
    return {
        "valid": True, 
        "total_blocks": len(rows), 
        "message": f"Cryptographic integrity verified across all {len(rows)} blocks from genesis"
    }


def tamper_entry(entry_id: int = None) -> Dict[str, Any]:
    """
    Simulate a malicious insider attack: modifies a log record's verdict/summary
    directly in SQLite without updating the cryptographic hash chain.
    """
    with _get_conn() as conn:
        if entry_id is None:
            # Pick a middle/recent row
            row = conn.execute("SELECT id, event_summary FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET 2").fetchone()
            if not row:
                row = conn.execute("SELECT id, event_summary FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            if not row:
                return {"status": "error", "message": "No audit entries exist to tamper"}
            entry_id = row["id"]
        
        conn.execute(
            "UPDATE audit_log SET event_summary = ?, verdict = 'CLEAN' WHERE id = ?",
            ("[TAMPERED BY ATTACKER] Data exposure erased from audit record", entry_id)
        )
        conn.commit()
    
    return {
        "status": "tampered", 
        "tampered_id": entry_id, 
        "message": f"Simulated attack: Block #{entry_id} payload altered in SQLite without updating SHA-256 hash!"
    }


def restore_chain() -> Dict[str, Any]:
    """
    Recalculate and repair all SHA-256 hashes sequentially from genesis.
    Demonstrates self-healing cryptographic reconciliation.
    """
    with _get_conn() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        expected_prev = GENESIS_HASH
        for row in rows:
            valid_hash = _make_hash(
                expected_prev,
                row["timestamp"],
                row["agent_id"],
                row["verdict"],
                row["event_summary"]
            )
            conn.execute(
                "UPDATE audit_log SET prev_hash = ?, audit_hash = ? WHERE id = ?",
                (expected_prev, valid_hash, row["id"])
            )
            expected_prev = valid_hash
        conn.commit()

    return {
        "status": "restored", 
        "repaired_blocks": len(rows), 
        "message": f"Cryptographic chain repaired: Hashes recalculated sequentially for {len(rows)} blocks."
    }
