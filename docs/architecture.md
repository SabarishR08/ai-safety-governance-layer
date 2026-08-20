# Sentinel — System Architecture

## Overview

Sentinel is a real-time AI safety middleware that intercepts all traffic between users/AI agents and the LLM. It operates as a **transparent proxy** — the LLM receives only clean, sanitised payloads.

## Data Flow

```
[User / AI Agent]
       │
       │  raw prompt / tool response
       ▼
┌──────────────────────────────────────────────────────┐
│                 Sentinel Backend (FastAPI)            │
│                                                      │
│  POST /api/inspect                                   │
│         │                                            │
│         ▼                                            │
│  ┌─────────────────────────────────────────────┐     │
│  │             Detection Pipeline              │     │
│  │                                             │     │
│  │  1. Regex PII Scanner                       │     │
│  │     └─ email, phone, Aadhaar, PAN, SSN,     │     │
│  │        credit card, API key, IP             │     │
│  │                                             │     │
│  │  2. Injection Heuristics                    │     │
│  │     └─ "ignore instructions", DAN mode,     │     │
│  │        jailbreak patterns                   │     │
│  │                                             │     │
│  │  3. Encoded Payload Detection               │     │
│  │     └─ base64 / hex decode + re-scan        │     │
│  │                                             │     │
│  │  Verdict Engine                             │     │
│  │     CLEAN → pass through                   │     │
│  │     MASKED → replace entities, forward     │     │
│  │     BLOCKED → stop, do not forward         │     │
│  └─────────────────────────────────────────────┘     │
│         │                                            │
│         ▼                                            │
│  Risk Aggregator (0–100 score)                       │
│  Audit Writer (SHA-256 hash chain → SQLite)          │
│  Event Writer (SQLite)                               │
│  WebSocket Broadcast (/ws/stream)                    │
└──────────────────────────────────────────────────────┘
       │
       │  clean payload (CLEAN or MASKED only)
       ▼
  [LLM / Downstream Tool]
```

## Audit Log Hash Chain

Each audit entry is signed with:

```
hash_n = SHA-256(hash_{n-1} | timestamp | agent_id | verdict | summary)
```

This means:
- Deleting any row breaks all subsequent hashes
- Modifying any field breaks the chain at that point
- The genesis hash is `0000...0000`

## Risk Scoring

Risk score per scan:
- Base: max weight of detected entity types
- Bonus: +5 per additional entity (capped at +20)
- Injection: forced to 95+

Session aggregate:
- Sliding window of last 500 scans
- High-risk events (score > 70) are double-weighted

## PII Entity Weights

| Entity Type   | Action | Risk Weight |
|---------------|--------|-------------|
| SSN           | BLOCK  | 95          |
| Aadhaar       | BLOCK  | 90          |
| Gov ID (PAN)  | BLOCK  | 90          |
| Credit Card   | MASK   | 85          |
| API Key       | STRIP  | 80          |
| Phone         | MASK   | 40          |
| Email         | MASK   | 30          |
| IP Address    | FLAG   | 25          |

## Technology Stack

| Layer | Technology |
|---|---|
| API server | FastAPI + Uvicorn |
| Detection | Regex + Presidio NER (optional) |
| Persistence | SQLite (audit + events) |
| Real-time | WebSocket (FastAPI native) |
| Dashboard | Vanilla HTML/CSS/JS (single file) |
| Deployment | Any Python 3.11+ environment |
