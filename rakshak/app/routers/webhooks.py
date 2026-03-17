"""Webhooks router — FR-21."""
import json
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.webhook import Webhook
from app.models.user import User
from app.dependencies import require_admin, require_any_role

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


class WebhookRequest(BaseModel):
    url: str
    events: list[str] = ["scan_complete", "critical_finding", "cert_expiration"]
    secret: Optional[str] = None


@router.post("")
async def register_webhook(
    req: WebhookRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    webhook = Webhook(
        url=req.url,
        events_json=json.dumps(req.events),
        secret=req.secret,
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    return {"webhook_id": webhook.id, "url": webhook.url, "events": req.events}


@router.get("")
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    result = await db.execute(select(Webhook))
    hooks = result.scalars().all()
    return [{"id": h.id, "url": h.url, "events": json.loads(h.events_json),
             "is_active": h.is_active, "last_triggered": h.last_triggered} for h in hooks]


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    from fastapi import HTTPException
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    hook = result.scalar_one_or_none()
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(hook)
    await db.commit()
    return {"message": "Webhook deleted"}
