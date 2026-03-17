"""Cyber Rating router — FR-47 through FR-50."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.asset import Asset, PQCLabel
from app.models.webhook import CyberRatingHistory
from app.models.user import User
from app.dependencies import require_any_role
from app.engine.rating_engine import compute_enterprise_score, COMPLIANCE_MATRIX, CLASSIFICATION_TABLE

router = APIRouter(prefix="/api/rating", tags=["rating"])


@router.get("")
async def get_rating(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-47, FR-48, FR-49: Enterprise cyber rating score with compliance matrix."""
    result = await db.execute(select(Asset))
    assets = result.scalars().all()

    counts = {
        "fully_quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.fully_quantum_safe),
        "pqc_ready": sum(1 for a in assets if a.pqc_label == PQCLabel.pqc_ready),
        "quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.quantum_safe),
        "not_quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.not_quantum_safe),
        "unknown": sum(1 for a in assets if a.pqc_label == PQCLabel.unknown),
    }
    return compute_enterprise_score(counts)


@router.get("/history")
async def get_rating_history(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """FR-50: Historical trend analysis."""
    result = await db.execute(
        select(CyberRatingHistory).order_by(CyberRatingHistory.recorded_at.asc())
    )
    rows = result.scalars().all()
    return [
        {
            "score": r.score,
            "tier": r.tier,
            "total_assets": r.total_assets,
            "fully_quantum_safe": r.fully_quantum_safe,
            "pqc_ready": r.pqc_ready,
            "quantum_safe": r.quantum_safe,
            "not_quantum_safe": r.not_quantum_safe,
            "recorded_at": r.recorded_at,
        }
        for r in rows
    ]
