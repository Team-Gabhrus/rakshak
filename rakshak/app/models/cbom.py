from datetime import datetime
from sqlalchemy import String, DateTime, Text, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class CBOMSnapshot(Base):
    __tablename__ = "cbom_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("assets.id"), nullable=True)
    target_url: Mapped[str] = mapped_column(String(2048))

    # CERT-IN Annexure-A four categories stored as JSON
    algorithms_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    keys_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    protocols_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificates_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    pqc_label: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    snapshot_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # SHA-256 of snapshot
