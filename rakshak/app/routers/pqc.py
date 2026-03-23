"""PQC Posture router — FR-41 through FR-46."""
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.asset import Asset, PQCLabel, RiskLevel
from app.models.scan import ScanResult
from app.models.user import User
from app.dependencies import require_any_role
from app.engine.playbook_generator import generate_playbook, generate_risk_timeline
from app.engine.rating_engine import COMPLIANCE_MATRIX

router = APIRouter(prefix="/api/pqc", tags=["pqc"])


@router.get("/posture")
async def get_pqc_posture(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-41: PQC compliance dashboard categorization."""
    result = await db.execute(select(Asset))
    assets = result.scalars().all()

    categories = {
        "elite_pqc_ready": [],
        "standard": [],
        "legacy": [],
        "critical": [],
    }

    for a in assets:
        label = a.pqc_label.value if a.pqc_label else "unknown"
        asset_info = {
            "id": a.id, "name": a.name, "url": a.url,
            "pqc_label": label, "risk_level": a.risk_level.value if a.risk_level else None,
            "tls_version": a.tls_version, "cipher_suite": a.cipher_suite,
            "key_length": a.key_length, "owner": a.owner, "last_scan": a.last_scan,
        }
        if label == "fully_quantum_safe":
            categories["elite_pqc_ready"].append(asset_info)
        elif label == "pqc_ready":
            categories["standard"].append(asset_info)
        elif label == "partially_quantum_safe":
            categories["legacy"].append(asset_info)
        else:
            categories["critical"].append(asset_info)

    # FR-43: Improvement recommendations summary
    recommendations_summary = []
    result2 = await db.execute(select(ScanResult).order_by(ScanResult.scanned_at.desc()).limit(100))
    scan_results = result2.scalars().all()
    rec_set = set()
    for sr in scan_results:
        if sr.recommendations_json:
            recs = json.loads(sr.recommendations_json)
            for rec in recs:
                if isinstance(rec, dict):
                    action = rec.get("action", "")
                    component = rec.get("component", "")
                    priority = rec.get("priority", "")
                else:
                    action = str(rec)
                    component = "Network"
                    priority = "Critical"

                if action not in rec_set:
                    rec_set.add(action)
                    recommendations_summary.append({
                        "component": component,
                        "action": action,
                        "priority": priority,
                        "target": sr.target_url,
                    })

    # FR-45 & FR-46 Dynamic Timeline
    has_vulnerable_kex = False
    has_vulnerable_auth = False
    for sr in scan_results:
        kex = sr.key_exchange or ""
        auth = sr.authentication or ""
        if kex and kex not in ["ML-KEM", "ML-KEM-768", "ML-KEM-1024", "Unknown"]:
            has_vulnerable_kex = True
        if auth and auth not in ["ML-DSA", "SLH-DSA", "Unknown"]:
            has_vulnerable_auth = True

    dynamic_timeline = generate_risk_timeline("RSA" if has_vulnerable_kex else "ML-KEM", "RSA" if has_vulnerable_auth else "ML-DSA")

    return {
        "categories": categories,
        "counts": {k: len(v) for k, v in categories.items()},
        "improvement_recommendations": recommendations_summary[:20],
        "risk_timeline": dynamic_timeline,
    }


@router.get("/recommendations/{asset_id}")
async def get_recommendations(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-12, FR-46: Migration playbook for a specific asset."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Get latest scan result for this asset
    sr_result = await db.execute(
        select(ScanResult).where(ScanResult.asset_id == asset_id).order_by(ScanResult.scanned_at.desc()).limit(1)
    )
    sr = sr_result.scalar_one_or_none()

    # Also search by URL
    if not sr:
        sr_result = await db.execute(
            select(ScanResult).where(ScanResult.target_url == asset.url).order_by(ScanResult.scanned_at.desc()).limit(1)
        )
        sr = sr_result.scalar_one_or_none()

    if not sr:
        raise HTTPException(status_code=404, detail="No scan results found for this asset")

    playbook = json.loads(sr.playbook_json) if sr.playbook_json else generate_playbook(
        asset.url, asset.tls_version, None, None, asset.cipher_suite, None, asset.pqc_label.value if asset.pqc_label else "unknown"
    )
    recommendations = json.loads(sr.recommendations_json) if sr.recommendations_json else []
    risk_timeline = generate_risk_timeline(sr.key_exchange, sr.authentication)

    return {
        "asset_id": asset_id,
        "asset_name": asset.name,
        "url": asset.url,
        "pqc_label": asset.pqc_label.value if asset.pqc_label else "unknown",
        "recommendations": recommendations,
        "playbook": playbook,
        "risk_timeline": risk_timeline,
    }


@router.get("/risk-timeline/{asset_id}")
async def get_risk_timeline(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-45: Quantum risk timeline for an asset."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    sr_result = await db.execute(
        select(ScanResult).where(ScanResult.target_url == asset.url).order_by(ScanResult.scanned_at.desc()).limit(1)
    )
    sr = sr_result.scalar_one_or_none()
    kex = sr.key_exchange if sr else None
    auth = sr.authentication if sr else None

    return generate_risk_timeline(kex, auth)
