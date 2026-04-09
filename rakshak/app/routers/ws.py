"""WebSocket router — FR-08 real-time scan progress."""
import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.scan_service import scan_progress
from app.services.subdomain_service import subdomain_scan_progress, get_subdomain_job

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


@router.websocket("/ws/subdomain/{job_id}")
async def subdomain_progress_ws(websocket: WebSocket, job_id: str):
    await websocket.accept()
    sent_count = 0
    try:
        while True:
            messages = subdomain_scan_progress.get(job_id, [])
            if len(messages) > sent_count:
                for msg in messages[sent_count:]:
                    await websocket.send_text(json.dumps(msg))
                    sent_count += 1
                    if msg.get("phase") in {"completed", "failed"}:
                        await websocket.close()
                        return

            job = get_subdomain_job(job_id)
            if job and job.get("status") in {"completed", "failed"} and sent_count >= len(messages):
                await websocket.close()
                return
            await asyncio.sleep(0.3)
    except WebSocketDisconnect:
        pass
