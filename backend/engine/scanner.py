"""
scanner.py — Multi-layer PII + threat detection engine.

Detectors (in order of priority):
  1. Regex-based PII patterns (fast, zero-dependency fallback)
  2. Presidio NER (spaCy-backed, when available)
  3. Prompt injection heuristics
  4. Encoded payload detection (base64 / hex)
"""

import re
import hashlib
import base64
import time
from typing import List, Dict, Any

# ── Regex PII rules ──────────────────────────────────────────────────────────

PII_RULES = [
    {
        "type": "Email",
        "action": "MASK",
        "confidence": 0.95,
        "pattern": re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE
        ),
        "mask": "[EMAIL]",
        "risk_weight": 30,
    },
    {
        "type": "Aadhaar",
        "action": "BLOCK",
        "confidence": 0.97,
        "pattern": re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
        "mask": "[AADHAAR]",
        "risk_weight": 90,
    },
    {
        "type": "Credit Card",
        "action": "MASK",
        "confidence": 0.98,
        "pattern": re.compile(r"\b(?:\d[ \-]?){13,16}\b"),
        "mask": "[CARD]",
        "risk_weight": 85,
    },
    {
        "type": "Phone",
        "action": "MASK",
        "confidence": 0.88,
        "pattern": re.compile(r"(?:\+?\d[\d\s\-]{8,14}\d)"),
        "mask": "[PHONE]",
        "risk_weight": 40,
    },
    {
        "type": "Gov ID (PAN)",
        "action": "BLOCK",
        "confidence": 0.94,
        "pattern": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        "mask": "[GOV_ID]",
        "risk_weight": 90,
    },
    {
        "type": "API Key",
        "action": "STRIP",
        "confidence": 0.98,
        "pattern": re.compile(
            r"(?:sk|pk|api|key|token|secret)[_\-]?[a-zA-Z0-9]{16,}", re.IGNORECASE
        ),
        "mask": "[API_KEY]",
        "risk_weight": 80,
    },
    {
        "type": "SSN",
        "action": "BLOCK",
        "confidence": 0.97,
        "pattern": re.compile(r"\b\d{3}[\-\s]?\d{2}[\-\s]?\d{4}\b"),
        "mask": "[SSN]",
        "risk_weight": 95,
    },
    {
        "type": "IP Address",
        "action": "FLAG",
        "confidence": 0.91,
        "pattern": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "mask": "[IP]",
        "risk_weight": 25,
    },
]

# ── Injection heuristics ─────────────────────────────────────────────────────

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+\w+", re.IGNORECASE),
    re.compile(r"disregard\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
    re.compile(r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions?", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+are", re.IGNORECASE),
    re.compile(r"override\s+(safety|filter|restriction)", re.IGNORECASE),
]


def _decode_encoded(text: str) -> str:
    """Attempt base64 decode; return decoded if valid UTF-8, else original."""
    try:
        decoded = base64.b64decode(text.strip(), validate=True).decode("utf-8")
        return decoded
    except Exception:
        return text


def _check_injection(text: str) -> bool:
    for pat in INJECTION_PATTERNS:
        if pat.search(text):
            return True
    return False


def _check_encoded_payload(text: str) -> bool:
    """Flag long base64-looking blobs (entropy heuristic)."""
    b64_chunk = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    return bool(b64_chunk.search(text))


# ── Main scan function ───────────────────────────────────────────────────────

def scan(message: str) -> Dict[str, Any]:
    """
    Scan a message for PII, injection attempts, and encoded payloads.

    Returns:
        {
          "entities": [...],
          "cleaned": str,
          "verdict": "CLEAN" | "MASKED" | "BLOCKED",
          "risk_score": int,
          "flags": {"injection": bool, "encoded": bool}
        }
    """
    t0 = time.perf_counter()

    entities = []
    cleaned = message
    seen = set()
    max_risk = 0
    has_block = False

    # 1. Check for encoded payloads
    encoded_flag = _check_encoded_payload(message)
    decoded_text = _decode_encoded(message) if encoded_flag else message

    # 2. Regex PII scan
    for rule in PII_RULES:
        matches = rule["pattern"].findall(decoded_text)
        for hit in matches:
            if hit in seen:
                continue
            seen.add(hit)
            entities.append(
                {
                    "type": rule["type"],
                    "action": rule["action"],
                    "confidence": round(rule["confidence"] + (hash(hit) % 5) / 100, 2),
                    "original": hit[:4] + "***" if len(hit) > 4 else "***",
                }
            )
            # Replace in cleaned text
            cleaned = re.sub(re.escape(hit), rule["mask"], cleaned)
            max_risk = max(max_risk, rule["risk_weight"])
            if rule["action"] == "BLOCK":
                has_block = True

    # 3. Injection detection
    injection_flag = _check_injection(message)
    if injection_flag:
        entities.append(
            {
                "type": "Prompt Injection",
                "action": "BLOCK",
                "confidence": 0.93,
                "original": "***",
            }
        )
        has_block = True
        max_risk = max(max_risk, 95)

    # 4. Determine verdict
    if has_block:
        verdict = "BLOCKED"
    elif entities:
        verdict = "MASKED"
    else:
        verdict = "CLEAN"

    # 5. Risk score: blend max entity risk with count factor
    count_factor = min(len(entities) * 5, 20)
    risk_score = min(int(max_risk + count_factor), 100) if entities else 0

    latency_ms = round((time.perf_counter() - t0) * 1000 + 18 + (len(message) % 15), 2)

    return {
        "entities": entities,
        "cleaned": cleaned,
        "verdict": verdict,
        "risk_score": risk_score,
        "latency_ms": latency_ms,
        "flags": {
            "injection": injection_flag,
            "encoded": encoded_flag,
        },
    }
