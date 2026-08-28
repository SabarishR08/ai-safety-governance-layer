# AI Safety & Governance Layer — Sentinel

> **PEC Techathon 4.0** · Track: Responsible AI, Compliance & Security

A real-time AI safety framework that identifies PII, masks sensitive information, and generates tamper-evident audit logs across all connected AI agents.

---

## Problem Statement

*"Organisations need mechanisms to prevent sensitive data exposure in AI systems. Build a framework that identifies PII, masks sensitive information and generates audit logs."*

---

## Solution Architecture

```
User / AI Agent
      │
      ▼
┌─────────────────────────────────────┐
│        Sentinel Interception Layer  │
│                                     │
│  ┌──────────┐   ┌────────────────┐  │
│  │  PII     │   │  Toxicity      │  │
│  │  Scanner │   │  Detector      │  │
│  └──────────┘   └────────────────┘  │
│  ┌──────────┐   ┌────────────────┐  │
│  │ Injection│   │  Policy        │  │
│  │ Detector │   │  Engine        │  │
│  └──────────┘   └────────────────┘  │
│                                     │
│  Verdict: CLEAN / MASKED / BLOCKED  │
└─────────────────────────────────────┘
      │
      ▼
  LLM / Tool Call (clean payload only)
      │
      ▼
  SHA-256 Audit Log
```

---

## Features

| Feature | Description |
|---|---|
| **PII Detection** | Identifies emails, phone numbers, Aadhaar, PAN, SSN, credit cards, API keys, IP addresses |
| **ML Toxicity & Threat Detection** | Uses `detoxify` (BERT-based) to identify and block toxic inputs and prompt injection |
| **Masking** | Replaces sensitive entities with typed placeholders `[EMAIL]`, `[AADHAAR]`, etc. |
| **Blocking** | Stops critical exposures (Gov IDs, SSN, Toxicity) from ever reaching the LLM |
| **Audit Logs** | SHA-256 hash-chained, tamper-evident ledger with full backend cryptographic verification |
| **Risk Scoring** | 0–100 weighted risk score across all active sessions |
| **Live Dashboard** | Real-time SOC dashboard — event stream, agents, rules, reports |
| **Playground** | Interactive UI to test interception live |

---

## Project Structure

```
ai-safety-governance-layer/
│
├── backend/                    # FastAPI inspection engine
│   ├── main.py                 # App entry point + routes
│   ├── engine/
│   │   ├── scanner.py          # PII + injection detection logic
│   │   ├── masker.py           # Entity masking / replacement
│   │   ├── auditor.py          # Hash-chained audit log writer
│   │   └── risk.py             # Risk score aggregator
│   ├── models/
│   │   └── schemas.py          # Pydantic request/response models
│   ├── db/
│   │   └── database.py         # SQLite connection + queries
│   └── requirements.txt        # Python dependencies
│
├── frontend/
│   └── sentinel-dashboard.html # Full SOC dashboard (single-file)
│
├── docs/
│   └── architecture.md         # System design notes
│
├── .gitignore
└── README.md
```

---

## Quick Start

### The Easy Way
Simply run the included startup script from the root directory:
```bash
python run.py
```
This will automatically install dependencies and start the server.

### Manual Setup
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Dashboard
Open `http://localhost:8000` in any browser (served automatically).

API docs available at: `http://localhost:8000/docs`

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/inspect` | Scan a message for PII and threats |
| `GET` | `/api/events` | Fetch recent scan events |
| `GET` | `/api/audit` | Fetch hash-chained audit log |
| `GET` | `/api/stats` | Aggregate risk stats |
| `GET` | `/api/agents` | Connected agent status |
| `WS` | `/ws/stream` | Real-time event stream (WebSocket) |

---

## Sample Request

```json
POST /api/inspect
{
  "message": "My aadhaar is 1234 5678 9012 and email is john@example.com",
  "agent_id": "agent-01",
  "session_id": "sess_abc123"
}
```

**Response:**
```json
{
  "verdict": "BLOCKED",
  "cleaned_message": "My aadhaar is [AADHAAR] and email is [EMAIL]",
  "entities": [
    { "type": "Aadhaar", "action": "BLOCK", "confidence": 0.97 },
    { "type": "Email",   "action": "MASK",  "confidence": 0.95 }
  ],
  "risk_score": 87,
  "latency_ms": 23,
  "audit_hash": "a9f3c1...21c"
}
```

---

## Team

Built for **PEC Techathon 4.0** — Responsible AI, Compliance & Security track.

---

## License

MIT
