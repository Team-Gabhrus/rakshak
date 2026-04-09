"""Scan router — FR-01, FR-08, FR-09."""
import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.scan import Scan, ScanResult, ScanStatus
from app.models.user import User
from app.dependencies import require_admin, require_any_role
from app.services.scan_service import validate_targets, run_scan, scan_progress, scan_cancel_events, push_progress
from app.services.audit_service import log_event
from app.config import settings
import csv
import io

router = APIRouter(prefix="/api/scan", tags=["scan"])


class ScanRequest(BaseModel):
    targets: list[str]
    discover_subdomains: bool = False


@router.post("")
async def submit_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    all_targets = req.targets.copy()
    if req.discover_subdomains:
        from app.services.subdomain_service import discover_subdomains
        from urllib.parse import urlparse
        for t in req.targets:
            parsed = urlparse(t if "://" in t else f"https://{t}")
            root_domain = parsed.netloc or parsed.path
            try:
                res = await discover_subdomains(root_domain, db)
                if "live_hosts" in res and res["live_hosts"]:
                    all_targets.extend(res["live_hosts"])
            except Exception as e:
                print(f"Error discovering subdomains for {t}: {e}")
                
    valid_targets, errors = validate_targets(list({t for t in all_targets if t}))

    if not valid_targets:
        raise HTTPException(status_code=422, detail={"message": "No valid targets provided", "errors": errors})

    scan = Scan(
        targets_json=json.dumps(valid_targets),
        target_count=len(valid_targets),
        created_by=current_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    await log_event(db, "scan_initiated", f"Scan #{scan.id} started with {len(valid_targets)} targets", current_user.id, current_user.username, request.client.host if request.client else None)

    # Run scan in background
    background_tasks.add_task(run_scan, scan.id, valid_targets, settings.DATABASE_URL)

    return {
        "scan_id": scan.id,
        "target_count": len(valid_targets),
        "validation_errors": errors,
        "status": "queued",
        "websocket_url": f"/ws/scan/{scan.id}",
    }


@router.post("/bulk-import")
async def bulk_import(
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """FR-36: Bulk CSV/JSON import."""
    from fastapi import UploadFile, File
    body = await request.body()
    content_type = request.headers.get("content-type", "")

    targets = []
    if "json" in content_type:
        data = json.loads(body)
        targets = data if isinstance(data, list) else data.get("targets", [])
    else:
        # CSV
        text = body.decode()
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if row:
                targets.append(row[0].strip())

    valid_targets, errors = validate_targets(targets)
    if not valid_targets:
        raise HTTPException(status_code=422, detail={"errors": errors})

    scan = Scan(targets_json=json.dumps(valid_targets), target_count=len(valid_targets), created_by=current_user.id)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    background_tasks.add_task(run_scan, scan.id, valid_targets, settings.DATABASE_URL)

    return {"scan_id": scan.id, "target_count": len(valid_targets), "validation_errors": errors}


@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    progress = scan_progress.get(scan_id, [])
    last_msg = progress[-1] if progress else {}
    return {
        "scan_id": scan_id,
        "status": scan.status.value,
        "progress_pct": scan.progress_pct,
        "target_count": scan.target_count,
        "completed_count": scan.completed_count,
        "failed_count": scan.failed_count,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "last_message": last_msg,
    }


@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    result = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
    rows = result.scalars().all()
    results = []
    for r in rows:
        results.append({
            "id": r.id,
            "target": r.target_url,
            "status": r.status,
            "tls_version": r.tls_version,
            "negotiated_cipher": r.negotiated_cipher,
            "key_exchange": r.key_exchange,
            "authentication": r.authentication,
            "encryption": r.encryption,
            "hashing": r.hashing,
            "pqc_label": r.pqc_label,
            "cert_subject": r.cert_subject,
            "cert_issuer": r.cert_issuer,
            "cert_not_after": r.cert_not_after,
            "cert_key_length": r.cert_key_length,
            "recommendations": json.loads(r.recommendations_json) if r.recommendations_json else [],
            "scanned_at": r.scanned_at,
        })
        
    return results


@router.get("/{scan_id}/details")
async def get_scan_details(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """Retrieve detailed target breakdown for an active or completed scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    targets = json.loads(scan.targets_json) if scan.targets_json else []
    
    res_query = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
    rows = res_query.scalars().all()
    
    completed_targets = {r.target_url for r in rows if r.status == "success"}
    intranet_only_targets = {r.target_url for r in rows if (r.pqc_label or "") == "intranet_only"}
    dns_failed_targets = {r.target_url for r in rows if (r.pqc_label or "") == "dns_failed"}
    invalid_targets = {
        r.target_url for r in rows
        if r.status in ["failed", "timeout"] and (
            (r.error_message or "").lower().startswith("invalid target")
            or (r.pqc_label or "") == "invalid_target"
        )
    }
    issue_targets = [
        {
            "target": r.target_url,
            "message": r.error_message or "Scan issue",
            "label": r.pqc_label or "unknown",
        }
        for r in rows
        if r.status in ["failed", "timeout"]
        and r.target_url not in intranet_only_targets
        and r.target_url not in dns_failed_targets
        and r.target_url not in invalid_targets
    ]

    classified = completed_targets | intranet_only_targets | dns_failed_targets | invalid_targets | {item["target"] for item in issue_targets}
    running_targets = [t for t in targets if t not in classified]
    
    return {
        "scan_id": scan_id,
        "status": scan.status.value,
        "total_targets": len(targets),
        "succeeded": sorted(list(completed_targets)),
        "intranet_only": sorted(list(intranet_only_targets)),
        "dns_failed": sorted(list(dns_failed_targets)),
        "failed": sorted(list(invalid_targets)),
        "issues": issue_targets,
        "running": sorted(running_targets)
    }


@router.delete("/{scan_id}")
async def cancel_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == ScanStatus.completed:
        return {"message": f"Scan {scan_id} is already completed", "status": scan.status.value}
    if scan.status == ScanStatus.failed:
        return {"message": f"Scan {scan_id} has already failed", "status": scan.status.value}

    if scan.status == ScanStatus.queued:
        scan.status = ScanStatus.cancelled
        scan.completed_at = scan.completed_at or scan.created_at
        await db.commit()
        await push_progress(scan_id, {
            "phase": "done",
            "status": "cancelled",
            "total": scan.target_count,
            "completed": scan.completed_count,
            "failed": scan.failed_count,
            "message": "Scan cancelled before execution started.",
        })
        return {"message": f"Scan {scan_id} cancelled", "status": scan.status.value}

    cancel_event = scan_cancel_events.get(scan_id)
    if cancel_event:
        cancel_event.set()
        await db.commit()
        return {"message": f"Scan {scan_id} cancellation requested", "status": "cancellation_requested"}

    scan.status = ScanStatus.cancelled
    await db.commit()
    return {"message": f"Scan {scan_id} cancelled", "status": scan.status.value}


@router.get("")
async def list_scans(
    start: str = None,
    end: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    query = select(Scan).order_by(Scan.created_at.desc())
    if start:
        from datetime import datetime
        query = query.where(Scan.created_at >= datetime.fromisoformat(start))
    if end:
        from datetime import datetime
        query = query.where(Scan.created_at <= datetime.fromisoformat(end))

    result = await db.execute(query)
    scans = result.scalars().all()

    def display_status(scan: Scan) -> str:
        cancel_event = scan_cancel_events.get(scan.id)
        if scan.status == ScanStatus.running and cancel_event and cancel_event.is_set():
            return "cancelling"
        return scan.status.value

    return [{"id": s.id, "status": s.status.value, "display_status": display_status(s), "target_count": s.target_count,
             "completed_count": s.completed_count, "progress_pct": s.progress_pct,
             "started_at": s.started_at, "completed_at": s.completed_at} for s in scans]
