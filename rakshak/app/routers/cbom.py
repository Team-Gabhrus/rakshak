"""CBOM router — FR-10, FR-13, FR-14."""
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.cbom import CBOMSnapshot
from app.models.user import User
from app.dependencies import require_any_role
from app.engine.cbom_generator import diff_cbom_snapshots

router = APIRouter(prefix="/api/cbom", tags=["cbom"])


@router.get("")
async def list_cbom(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    result = await db.execute(select(CBOMSnapshot).order_by(CBOMSnapshot.created_at.desc()))
    snaps = result.scalars().all()
    return [{"id": s.id, "target": s.target_url, "pqc_label": s.pqc_label,
             "created_at": s.created_at, "snapshot_hash": s.snapshot_hash} for s in snaps]


@router.get("/metrics")
async def cbom_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """CBOM module summary metrics."""
    result = await db.execute(select(CBOMSnapshot))
    snaps = result.scalars().all()
    total_apps = len(set(s.target_url for s in snaps))
    active_certs = 0
    weak_crypto = 0
    cert_issues = 0

    for s in snaps:
        if s.pqc_label in ("not_quantum_safe", "quantum_safe"):
            weak_crypto += 1
        certs = json.loads(s.certificates_json or "[]")
        active_certs += len(certs)
        from datetime import datetime
        for cert in certs:
            exp = cert.get("not_valid_after")
            if exp:
                try:
                    if datetime.fromisoformat(exp.replace("Z", "")) < datetime.utcnow():
                        cert_issues += 1
                except Exception:
                    pass

    return {
        "total_applications": total_apps,
        "sites_surveyed": len(snaps),
        "active_certificates": active_certs,
        "weak_cryptography": weak_crypto,
        "certificate_issues": cert_issues,
    }


@router.get("/{snap_id}")
async def get_cbom(
    snap_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-10: Full CBOM for a specific snapshot."""
    result = await db.execute(select(CBOMSnapshot).where(CBOMSnapshot.id == snap_id))
    snap = result.scalar_one_or_none()
    if not snap:
        raise HTTPException(status_code=404, detail="CBOM snapshot not found")
    return {
        "id": snap.id,
        "target": snap.target_url,
        "pqc_label": snap.pqc_label,
        "created_at": snap.created_at,
        "snapshot_hash": snap.snapshot_hash,
        "algorithms": json.loads(snap.algorithms_json or "[]"),
        "keys": json.loads(snap.keys_json or "[]"),
        "protocols": json.loads(snap.protocols_json or "[]"),
        "certificates": json.loads(snap.certificates_json or "[]"),
    }


@router.get("/compare")
async def compare_snapshots(
    snap_a: int = Query(..., description="ID of first CBOM snapshot"),
    snap_b: int = Query(..., description="ID of second CBOM snapshot"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-13: Compare two CBOM snapshots."""
    res_a = await db.execute(select(CBOMSnapshot).where(CBOMSnapshot.id == snap_a))
    res_b = await db.execute(select(CBOMSnapshot).where(CBOMSnapshot.id == snap_b))
    a = res_a.scalar_one_or_none()
    b = res_b.scalar_one_or_none()
    if not a or not b:
        raise HTTPException(status_code=404, detail="One or both snapshots not found")

    snap_a_dict = {
        "generated_at": a.created_at.isoformat(),
        "pqc_label": a.pqc_label,
        "algorithms": json.loads(a.algorithms_json or "[]"),
        "keys": json.loads(a.keys_json or "[]"),
        "protocols": json.loads(a.protocols_json or "[]"),
        "certificates": json.loads(a.certificates_json or "[]"),
    }
    snap_b_dict = {
        "generated_at": b.created_at.isoformat(),
        "pqc_label": b.pqc_label,
        "algorithms": json.loads(b.algorithms_json or "[]"),
        "keys": json.loads(b.keys_json or "[]"),
        "protocols": json.loads(b.protocols_json or "[]"),
        "certificates": json.loads(b.certificates_json or "[]"),
    }
    return diff_cbom_snapshots(snap_a_dict, snap_b_dict)


@router.get("/cert-chain/{snap_id}")
async def get_cert_chain(
    snap_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-14: Certificate chain visualization data."""
    result = await db.execute(select(CBOMSnapshot).where(CBOMSnapshot.id == snap_id))
    snap = result.scalar_one_or_none()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    certs = json.loads(snap.certificates_json or "[]")
    # Build tree structure for frontend visualization
    nodes = []
    edges = []
    for i, cert in enumerate(certs):
        label = "not_quantum_safe" if "RSA" in cert.get("key_algorithm", "") else snap.pqc_label
        nodes.append({
            "id": i,
            "label": cert.get("name", f"Cert {i}"),
            "pqc_label": label,
            "details": cert,
            "level": i,
        })
        if i > 0:
            edges.append({"from": i, "to": i - 1})
    return {"nodes": nodes, "edges": edges, "target": snap.target_url}
