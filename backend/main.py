import asyncio
import uuid
import time
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict

from backend.database import init_db, get_db, Policy, AuditLog
from backend.core.pii_detector import detector
from backend.core.audit import log_audit_event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

app = FastAPI(title="AI Data Firewall")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.on_event("startup")
async def on_startup():
    await init_db()
    # Start traffic simulator
    asyncio.create_task(simulate_traffic())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

class InterceptRequest(BaseModel):
    prompt: str
    session_id: str

@app.post("/intercept")
async def intercept_request(req: InterceptRequest, db: AsyncSession = Depends(get_db)):
    start_time = time.time()
    
    # Load policies
    result = await db.execute(select(Policy))
    policies = {p.entity_type: p.action for p in result.scalars().all()}
    
    # Defaults
    default_policies = {"EMAIL_ADDRESS": "MASK", "PHONE_NUMBER": "MASK", "SSN": "BLOCK", "CREDIT_CARD": "MASK"}
    for k, v in default_policies.items():
        if k not in policies:
            policies[k] = v

    # Detect
    detections = detector.detect(req.prompt)
    
    # Audit & Mask
    masked_prompt = detector.mask(req.prompt, detections, policies)
    
    audit_logs = []
    for det in detections:
        action = policies.get(det["entity_type"], "MASK").upper()
        log = await log_audit_event(db, req.session_id, det["entity_type"], action, det["score"])
        audit_logs.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "entity_type": log.entity_type,
            "action": log.action_taken,
            "score": log.confidence_score,
            "current_hash": log.current_hash,
            "prev_hash": log.previous_hash
        })
    
    latency_ms = (time.time() - start_time) * 1000

    # Broadcast event
    event = {
        "type": "INTERCEPT",
        "session_id": req.session_id,
        "original_length": len(req.prompt),
        "detections": detections,
        "latency_ms": latency_ms,
        "audit_logs": audit_logs,
        "masked_prompt": masked_prompt
    }
    await manager.broadcast(event)

    return {"sanitized_prompt": masked_prompt, "latency_ms": latency_ms, "detections": len(detections)}


@app.get("/policies")
async def get_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy))
    return [{"entity_type": p.entity_type, "action": p.action} for p in result.scalars().all()]


class PolicyUpdate(BaseModel):
    entity_type: str
    action: str

@app.post("/policies")
async def update_policy(update: PolicyUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.entity_type == update.entity_type))
    policy = result.scalars().first()
    if policy:
        policy.action = update.action
    else:
        policy = Policy(entity_type=update.entity_type, action=update.action, environment="production")
        db.add(policy)
    await db.commit()
    
    # Broadcast policy update
    await manager.broadcast({"type": "POLICY_UPDATE"})
    return {"status": "ok"}


@app.get("/audit_logs")
async def get_audit_logs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(100))
    logs = result.scalars().all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat(),
            "entity_type": l.entity_type,
            "action": l.action_taken,
            "score": l.confidence_score,
            "current_hash": l.current_hash[:8] + "...",
            "prev_hash": l.previous_hash[:8] + "..."
        } for l in logs
    ]

# Simulated Traffic
import random
import httpx

SAMPLE_PROMPTS = [
    "Hello, how are you?",
    "My email is john.doe@example.com, can you help me?",
    "Please update my file. SSN: 123-45-6789.",
    "Call me at 555-123-4567 regarding the project.",
    "I need to process a refund to card 4111222233334444.",
    "What is the weather like today?",
    "The diagnosis is positive, contact jane@hospital.org.",
    "My number is (800) 555-1234, call ASAP.",
]

async def simulate_traffic():
    async with httpx.AsyncClient(base_url="http://127.0.0.0:8000") as client:
        # Wait for server to be fully up
        await asyncio.sleep(2)
        while True:
            prompt = random.choice(SAMPLE_PROMPTS)
            req = {
                "prompt": prompt,
                "session_id": str(uuid.uuid4())[:8]
            }
            try:
                # Use a background task so we don't block
                from backend.database import AsyncSessionLocal
                async with AsyncSessionLocal() as db:
                    # To avoid httpx recursive call while server boots, we can just call the route handler logic directly.
                    # Actually httpx is fine if we use the correct port.
                    pass
                await client.post("http://127.0.0.1:8000/intercept", json=req)
            except Exception as e:
                pass
            
            # Random delay between requests
            await asyncio.sleep(random.uniform(0.5, 2.5))
