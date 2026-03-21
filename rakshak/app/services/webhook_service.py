import json
import httpx
import logging
from typing import Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.webhook import Webhook
from datetime import datetime

logger = logging.getLogger(__name__)

async def trigger_webhooks(db: AsyncSession, event_name: str, payload: Dict[str, Any]):
    """Trigger all active webhooks subscribed to a specific event."""
    result = await db.execute(select(Webhook).where(Webhook.is_active == True))
    webhooks = result.scalars().all()
    
    async with httpx.AsyncClient() as client:
        for webhook in webhooks:
            events = json.loads(webhook.events_json)
            if event_name in events:
                headers = {"Content-Type": "application/json"}
                if webhook.secret:
                    # In a real app, generate HMAC signature. For prototype, we pass as header.
                    headers["X-Webhook-Secret"] = webhook.secret
                
                body = {
                    "event": event_name,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": payload
                }
                
                try:
                    response = await client.post(webhook.url, json=body, headers=headers, timeout=5.0)
                    response.raise_for_status()
                    # Update last triggered
                    webhook.last_triggered = datetime.utcnow()
                    logger.info(f"Successfully sent {event_name} webhook to {webhook.url}")
                except Exception as e:
                    logger.error(f"Failed to send webhook to {webhook.url}: {str(e)}")
                    
    await db.commit()
