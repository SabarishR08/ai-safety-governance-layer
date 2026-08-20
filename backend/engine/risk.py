"""
risk.py — Session-level risk score aggregator.

Maintains an in-memory sliding window of recent scan results and
computes a weighted aggregate risk score (0–100) across all sessions.
"""

from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Any
import threading

# Thread-safe sliding window (last 500 events)
_lock = threading.Lock()
_window: Deque[Dict[str, Any]] = deque(maxlen=500)

# Session risk registry  {session_id: latest_risk_score}
_sessions: Dict[str, int] = {}

_start_time = datetime.now(timezone.utc)


def record(session_id: str, risk_score: int, verdict: str) -> None:
    """Record a scan result into the sliding window."""
    with _lock:
        _window.append(
            {
                "session_id": session_id,
                "risk_score": risk_score,
                "verdict": verdict,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )
        _sessions[session_id] = risk_score


def aggregate_risk() -> float:
    """
    Weighted average risk score across the sliding window.
    High-risk events (score > 70) are double-weighted.
    """
    with _lock:
        if not _window:
            return 0.0
        total_weight = 0
        weighted_sum = 0.0
        for entry in _window:
            w = 2 if entry["risk_score"] > 70 else 1
            weighted_sum += entry["risk_score"] * w
            total_weight += w
        return round(weighted_sum / total_weight, 1) if total_weight else 0.0


def session_breakdown() -> Dict[str, int]:
    """Return {critical: n, elevated: n, nominal: n} counts."""
    with _lock:
        critical = sum(1 for s in _sessions.values() if s >= 80)
        elevated = sum(1 for s in _sessions.values() if 40 <= s < 80)
        nominal = sum(1 for s in _sessions.values() if s < 40)
    return {"critical": critical, "elevated": elevated, "nominal": nominal}


def uptime_seconds() -> float:
    return (datetime.now(timezone.utc) - _start_time).total_seconds()
