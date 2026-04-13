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
from app.services.domain_service import get_cbom_history_by_target
from app.utils.domain_tools import get_root_domain

router = APIRouter(prefix="/api/cbom", tags=["cbom"])

VISIBLE_CBOM_LABELS = {
    "fully_quantum_safe",
    "pqc_ready",
    "partially_quantum_safe",
    "not_quantum_safe",
}


def _is_hidden_unknown_label(label: str | None) -> bool:
    normalized = (label or "unknown").strip().lower()
    return normalized not in VISIBLE_CBOM_LABELS


@router.get("")
async def list_cbom(
    domain: str = Query(None),
    include_unknown: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    history = await get_cbom_history_by_target(db)
    items = []
    for target, snapshots in history.items():
        latest = snapshots[0]
        root_domain = get_root_domain(target)
        if domain and root_domain != get_root_domain(domain):
            continue
        if not include_unknown and _is_hidden_unknown_label(latest.pqc_label):
            continue
        items.append({
            "id": latest.id,
            "target": latest.target_url,
            "hostname": latest.target_url.split("://")[-1].split("/")[0],
            "domain": root_domain,
            "pqc_label": latest.pqc_label,
            "created_at": latest.created_at,
            "snapshot_hash": latest.snapshot_hash,
            "history_count": len(snapshots),
            "has_history": len(snapshots) > 1,
        })
    domain_latest = {}
    for item in items:
        current = domain_latest.get(item["domain"])
        if current is None or item["created_at"] > current:
            domain_latest[item["domain"]] = item["created_at"]
    return sorted(
        items,
        key=lambda item: (domain_latest.get(item["domain"]), item["created_at"], item["target"]),
        reverse=True,
    )


@router.get("/metrics")
async def cbom_metrics(
    domain: str = Query(None),
    include_unknown: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """CBOM module summary metrics."""
    history = await get_cbom_history_by_target(db)
    snaps = []
    for target, target_history in history.items():
        latest = target_history[0]
        if domain and get_root_domain(target) != get_root_domain(domain):
            continue
        if not include_unknown and _is_hidden_unknown_label(latest.pqc_label):
            continue
        snaps.append(latest)

    total_apps = len(snaps)
    active_certs = 0
    weak_crypto = 0
    cert_issues = 0

    cipher_dist = {}
    key_length_dist = {}
    protocol_dist = {}

    from datetime import datetime
    for s in snaps:
        if s.pqc_label in ("not_quantum_safe", "partially_quantum_safe"):
            weak_crypto += 1
        
        # Cert issues and total certs
        certs = json.loads(s.certificates_json or "[]")
        active_certs += len(certs)
        for cert in certs:
            exp = cert.get("not_valid_after")
            if exp:
                try:
                    if datetime.fromisoformat(exp.replace("Z", "")) < datetime.utcnow():
                        cert_issues += 1
                except Exception:
                    pass

        # Cipher dist
        algs = json.loads(s.algorithms_json or "[]")
        for alg in algs:
            name = alg.get("name")
            if name:
                cipher_dist[name] = cipher_dist.get(name, 0) + 1

        # Key dist
        keys = json.loads(s.keys_json or "[]")
        for k in keys:
            size_str = k.get("size", "")
            if size_str:
                size = size_str.replace(" bits", "")
                key_length_dist[size] = key_length_dist.get(size, 0) + 1

        # Protocol dist
        protos = json.loads(s.protocols_json or "[]")
        for p in protos:
            version = p.get("version", "Unknown")
            if version:
                protocol_dist[version] = protocol_dist.get(version, 0) + 1

    return {
        "total_applications": total_apps,
        "sites_surveyed": len(snaps),
        "active_certificates": active_certs,
        "weak_cryptography": weak_crypto,
        "certificate_issues": cert_issues,
        "cipher_dist": cipher_dist,
        "key_length_dist": key_length_dist,
        "protocol_dist": protocol_dist,
    }


@router.get("/history")
async def cbom_history(
    target: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    history = await get_cbom_history_by_target(db, [target])
    snapshots = history.get(target, [])
    return [{
        "id": snapshot.id,
        "target": snapshot.target_url,
        "pqc_label": snapshot.pqc_label,
        "created_at": snapshot.created_at,
        "snapshot_hash": snapshot.snapshot_hash,
    } for snapshot in snapshots]


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


@router.get("/{snap_id}")
async def get_cbom(
    snap_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-10: Full CBOM for a specific snapshot."""
    from app.models.asset import Asset
    result = await db.execute(
        select(CBOMSnapshot, Asset.name)
        .outerjoin(Asset, CBOMSnapshot.target_url == Asset.url)
        .where(CBOMSnapshot.id == snap_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="CBOM snapshot not found")
    snap, asset_name = row
    return {
        "id": snap.id,
        "target": snap.target_url,
        "target_name": asset_name or snap.target_url,
        "pqc_label": snap.pqc_label,
        "created_at": snap.created_at,
        "snapshot_hash": snap.snapshot_hash,
        "algorithms": json.loads(snap.algorithms_json or "[]"),
        "keys": json.loads(snap.keys_json or "[]"),
        "protocols": json.loads(snap.protocols_json or "[]"),
        "certificates": json.loads(snap.certificates_json or "[]"),
    }


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
