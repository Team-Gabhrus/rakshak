"""PQC Posture router — FR-41 through FR-46."""
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.asset import Asset, PQCLabel, RiskLevel
from app.models.scan import ScanResult
from app.models.user import User
from app.dependencies import require_any_role
from app.engine.playbook_generator import generate_playbook, generate_risk_timeline
from app.engine.rating_engine import COMPLIANCE_MATRIX
from app.services.domain_service import get_assets_for_domains
from app.utils.domain_tools import get_root_domain

router = APIRouter(prefix="/api/pqc", tags=["pqc"])


@router.get("/posture")
async def get_pqc_posture(
    domain: str = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-41: PQC compliance dashboard categorization."""
    assets = await get_assets_for_domains(db, [domain] if domain else None)

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
        elif label == "not_quantum_safe":
            categories["critical"].append(asset_info)

    # FR-45 & FR-46 Dynamic Timeline
    has_vulnerable_kex = False
    has_vulnerable_auth = False
    scan_target_urls = [asset.url for asset in assets]
    result2 = await db.execute(select(ScanResult).order_by(ScanResult.scanned_at.desc()).limit(500))
    scan_results = [row for row in result2.scalars().all() if not scan_target_urls or row.target_url in scan_target_urls]
    for sr in scan_results:
        kex = (sr.key_exchange or "").upper().replace("-", "").replace("_", "")
        auth = (sr.authentication or "").upper().replace("-", "").replace("_", "")
        # Use contains-match so hybrid names like X25519_MLKEM768 are recognized
        if kex and not any(p in kex for p in ["MLKEM", "KYBER"]):
            has_vulnerable_kex = True
        if auth and not any(p in auth for p in ["MLDSA", "SLHDSA", "FALCON", "FNDSA", "DILITHIUM"]):
            has_vulnerable_auth = True

    dynamic_timeline = generate_risk_timeline("RSA" if has_vulnerable_kex else "ML-KEM", "RSA" if has_vulnerable_auth else "ML-DSA")

    return {
        "categories": categories,
        "counts": {k: len(v) for k, v in categories.items()},
        "risk_timeline": dynamic_timeline,
        "selected_domain": get_root_domain(domain) if domain else None,
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

    pqc_details = json.loads(sr.pqc_details_json) if sr.pqc_details_json else {}
    leaf_pqc_flag = pqc_details.get("leaf_pqc", False)
    full_chain_flag = pqc_details.get("cert_chain_pqc", False)

    playbook = json.loads(sr.playbook_json) if sr.playbook_json else generate_playbook(
        asset.url, sr.tls_version, sr.key_exchange, sr.authentication, sr.encryption, sr.hashing, asset.pqc_label.value if asset.pqc_label else "unknown",
        leaf_pqc=leaf_pqc_flag, full_chain_pqc=full_chain_flag, cert_sig_algo=sr.cert_sig_algorithm
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
