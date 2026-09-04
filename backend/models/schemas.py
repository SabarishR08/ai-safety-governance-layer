from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class InspectRequest(BaseModel):
    message: str = Field(..., description="The message/prompt to scan")
    agent_id: str = Field(default="agent-unknown", description="Source agent identifier")
    session_id: str = Field(default="sess-unknown", description="Session identifier")


class DetectedEntity(BaseModel):
    type: str
    action: str           # MASK | BLOCK | STRIP | FLAG
    confidence: float
    original: Optional[str] = None   # redacted in production logs
    reason: Optional[str] = None     # explainability: why this entity was flagged


class InspectResponse(BaseModel):
    verdict: str          # CLEAN | MASKED | BLOCKED
    cleaned_message: str
    entities: List[DetectedEntity]
    risk_score: int       # 0–100
    latency_ms: float
    audit_hash: str
    timestamp: str
    agent_id: str
    session_id: str


class AuditEntry(BaseModel):
    id: int
    timestamp: str
    agent_id: str
    session_id: str
    verdict: str
    event_summary: str
    risk_score: int
    audit_hash: str
    prev_hash: str


class StatsResponse(BaseModel):
    total_scanned: int
    total_masked: int
    total_blocked: int
    critical_exposures: int
    avg_latency_ms: float
    risk_score: float
    uptime_seconds: float


class AgentInfo(BaseModel):
    agent_id: str
    name: str
    endpoint: str
    status: str           # live | idle | elevated
    req_per_min: int
    avg_latency_ms: float


class EventRow(BaseModel):
    timestamp: str
    verdict: str
    description: str
    agent_id: str
    latency_ms: float
    risk_score: int
