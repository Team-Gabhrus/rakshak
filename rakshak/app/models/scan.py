import enum
from datetime import datetime
from sqlalchemy import String, DateTime, Enum as SAEnum, Text, Integer, ForeignKey, Float
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.queued)
    targets_json: Mapped[str] = mapped_column(Text, nullable=False)    # JSON list of targets
    target_count: Mapped[int] = mapped_column(Integer, default=0)
    completed_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    progress_pct: Mapped[float] = mapped_column(Float, default=0.0)
    created_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("assets.id"), nullable=True)
    target_url: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(50), default="success")  # success / failed / timeout
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # TLS Data
    tls_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cipher_suites_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    negotiated_cipher: Mapped[str | None] = mapped_column(String(255), nullable=True)
    key_exchange: Mapped[str | None] = mapped_column(String(100), nullable=True)
    authentication: Mapped[str | None] = mapped_column(String(100), nullable=True)
    encryption: Mapped[str | None] = mapped_column(String(100), nullable=True)
    hashing: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Certificate
    cert_chain_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    cert_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cert_issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cert_not_before: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cert_not_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cert_sig_algorithm: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cert_key_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cert_authority: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # PQC
    pqc_label: Mapped[str | None] = mapped_column(String(50), nullable=True)
    pqc_details_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    playbook_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
