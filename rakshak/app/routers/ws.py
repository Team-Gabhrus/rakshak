"""WebSocket router — FR-08 real-time scan progress."""
import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.scan_service import scan_progress

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scan/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    sent_count = 0
    try:
        while True:
            messages = scan_progress.get(scan_id, [])
            if len(messages) > sent_count:
                for msg in messages[sent_count:]:
                    await websocket.send_text(json.dumps(msg))
                    sent_count = len(messages)
                    if msg.get("phase") == "done":
                        await websocket.close()
                        return
            await asyncio.sleep(0.3)
    except WebSocketDisconnect:
        pass
