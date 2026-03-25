from datetime import datetime
from sqlalchemy import String, DateTime, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    events_json: Mapped[str] = mapped_column(Text, default='["scan_complete","critical_finding","cert_expiration"]')
    secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_triggered: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CyberRatingHistory(Base):
    __tablename__ = "cyber_rating_history"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    score: Mapped[float] = mapped_column(nullable=False)
    tier: Mapped[str] = mapped_column(String(50))
    total_assets: Mapped[int] = mapped_column(default=0)
    fully_quantum_safe: Mapped[int] = mapped_column(default=0)
    pqc_ready: Mapped[int] = mapped_column(default=0)
    partially_quantum_safe: Mapped[int] = mapped_column(default=0)
    not_quantum_safe: Mapped[int] = mapped_column(default=0)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
