import enum
from datetime import datetime
from sqlalchemy import String, DateTime, Enum as SAEnum, Text, Integer, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class ReportFormat(str, enum.Enum):
    json = "json"
    xml = "xml"
    csv = "csv"
    pdf = "pdf"


class DeliveryChannel(str, enum.Enum):
    email = "email"
    local = "local"
    slack = "slack"


class ReportFrequency(str, enum.Enum):
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), default="on_demand")  # on_demand / scheduled
    format: Mapped[ReportFormat] = mapped_column(SAEnum(ReportFormat), default=ReportFormat.pdf)
    delivery_channel: Mapped[DeliveryChannel] = mapped_column(SAEnum(DeliveryChannel), default=DeliveryChannel.local)
    modules_json: Mapped[str] = mapped_column(Text, default='["cbom","pqc","rating","inventory","discovery"]')
    asset_ids_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    include_charts: Mapped[bool] = mapped_column(Boolean, default=True)
    password_protected: Mapped[bool] = mapped_column(Boolean, default=False)
    password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    delivery_target: Mapped[str | None] = mapped_column(String(512), nullable=True)  # email / path / webhook
    status: Mapped[str] = mapped_column(String(50), default="pending")
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    frequency: Mapped[ReportFrequency] = mapped_column(SAEnum(ReportFrequency))
    format: Mapped[ReportFormat] = mapped_column(SAEnum(ReportFormat), default=ReportFormat.pdf)
    delivery_channel: Mapped[DeliveryChannel] = mapped_column(SAEnum(DeliveryChannel))
    modules_json: Mapped[str] = mapped_column(Text)
    asset_ids_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    include_charts: Mapped[bool] = mapped_column(Boolean, default=True)
    password_protected: Mapped[bool] = mapped_column(Boolean, default=False)
    delivery_target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
