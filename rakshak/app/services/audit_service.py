import hashlib
import json
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit import AuditLog


async def log_event(
    db: AsyncSession,
    event_type: str,
    event_details: str = "",
    user_id: int | None = None,
    username: str | None = None,
    ip_address: str | None = None,
):
    """Record an audit log entry with tamper-evident SHA-256 hash."""
    entry = AuditLog(
        user_id=user_id,
        username=username,
        event_type=event_type,
        event_details=event_details,
        ip_address=ip_address,
        timestamp=datetime.utcnow(),
    )
    db.add(entry)
    await db.flush()  # get the id

    # Compute tamper-evident hash
    payload = json.dumps({
        "id": entry.id,
        "user_id": user_id,
        "event_type": event_type,
        "event_details": event_details,
        "ip_address": ip_address,
        "timestamp": entry.timestamp.isoformat(),
    }, sort_keys=True)
    entry.log_hash = hashlib.sha256(payload.encode()).hexdigest()
    await db.commit()
    return entry
