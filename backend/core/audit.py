import hashlib
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.database import AuditLog

async def log_audit_event(session: AsyncSession, session_id: str, entity_type: str, action: str, score: float):
    # Get previous hash
    result = await session.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    )
    last_entry = result.scalars().first()
    prev_hash = last_entry.current_hash if last_entry else "0" * 64

    # Calculate new hash
    payload = {
        "session_id": session_id,
        "entity_type": entity_type,
        "action": action,
        "score": score,
        "prev_hash": prev_hash
    }
    payload_str = json.dumps(payload, sort_keys=True)
    current_hash = hashlib.sha256(payload_str.encode()).hexdigest()

    new_log = AuditLog(
        session_id=session_id,
        entity_type=entity_type,
        action_taken=action,
        confidence_score=score,
        previous_hash=prev_hash,
        current_hash=current_hash
    )
    session.add(new_log)
    await session.commit()
    return new_log
