import enum
from datetime import datetime
from sqlalchemy import String, Float, DateTime, Enum as SAEnum, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class AssetType(str, enum.Enum):
    web_app = "web_app"
    api = "api"
    vpn = "vpn"
    server = "server"


class RiskLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class PQCLabel(str, enum.Enum):
    not_quantum_safe = "not_quantum_safe"
    partially_quantum_safe = "partially_quantum_safe"
    pqc_ready = "pqc_ready"
    fully_quantum_safe = "fully_quantum_safe"
    unknown = "unknown"
    intranet_only = "intranet_only"   # DNS resolves but port is firewalled / intranet-only
    dns_failed = "dns_failed"         # Hostname does not resolve in public DNS


class DiscoveryStatus(str, enum.Enum):
    new = "new"
    confirmed = "confirmed"
    false_positive = "false_positive"


class DiscoveryCategory(str, enum.Enum):
    domain = "domain"
    ssl_cert = "ssl_cert"
    ip_subnet = "ip_subnet"
    software = "software"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    ipv4: Mapped[str | None] = mapped_column(String(15), nullable=True)
    ipv6: Mapped[str | None] = mapped_column(String(45), nullable=True)
    asset_type: Mapped[AssetType] = mapped_column(SAEnum(AssetType), default=AssetType.web_app)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_level: Mapped[RiskLevel] = mapped_column(SAEnum(RiskLevel), default=RiskLevel.unknown)
    pqc_label: Mapped[PQCLabel] = mapped_column(SAEnum(PQCLabel), default=PQCLabel.unknown)
    cert_expiry: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    key_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_scan: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    cyber_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cert_authority: Mapped[str | None] = mapped_column(String(255), nullable=True)


class NameserverRecord(Base):
    __tablename__ = "nameserver_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    domain: Mapped[str] = mapped_column(String(255))
    hostname: Mapped[str] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(15), nullable=True)
    record_type: Mapped[str] = mapped_column(String(10))
    ipv6_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    key_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cipher_suite_tls: Mapped[str | None] = mapped_column(String(255), nullable=True)
    certificate_authority: Mapped[str | None] = mapped_column(String(255), nullable=True)


class AssetDiscovery(Base):
    __tablename__ = "asset_discoveries"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    category: Mapped[DiscoveryCategory] = mapped_column(SAEnum(DiscoveryCategory))
    status: Mapped[DiscoveryStatus] = mapped_column(SAEnum(DiscoveryStatus), default=DiscoveryStatus.new)
    name: Mapped[str] = mapped_column(String(255))
    value: Mapped[str] = mapped_column(String(2048))
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
