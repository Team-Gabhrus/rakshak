"""
Scan Service — orchestrates the full scan lifecycle.
FR-01 (target input), FR-08 (WebSocket progress), FR-09 (input validation),
FR-05 (VPN), FR-06 (API).
"""
import asyncio
import json
import re
import ipaddress
import logging
from app.services.webhook_service import trigger_webhooks
from datetime import datetime
from typing import Optional, Callable
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scan import Scan, ScanResult, ScanStatus
from app.models.asset import Asset, PQCLabel, RiskLevel, AssetType
from app.models.cbom import CBOMSnapshot
from app.models.webhook import CyberRatingHistory
from app.engine import tls_scanner, pqc_classifier, cbom_generator, rating_engine, playbook_generator

logger = logging.getLogger(__name__)

# Global dict: scan_id -> list of progress messages (for WebSocket delivery)
scan_progress: dict[int, list[dict]] = {}


def validate_targets(targets: list[str]) -> tuple[list[str], list[str]]:
    """
    FR-09: Validate all target inputs.
    Returns (valid_targets, errors).
    """
    valid = []
    errors = []

    url_pattern = re.compile(
        r'^(https?://)?'
        r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        r'(:\d{1,5})?(/.*)?$'
    )

    for t in targets:
        t = t.strip()
        if not t:
            continue
        # Try IP
        try:
            ipaddress.ip_address(t.split(":")[0])
            valid.append(t)
            continue
        except ValueError:
            pass
        # Try CIDR
        try:
            ipaddress.ip_network(t, strict=False)
            valid.append(t)
            continue
        except ValueError:
            pass
        # Try URL/hostname
        if url_pattern.match(t):
            if not t.startswith("http"):
                t = "https://" + t
            valid.append(t)
        else:
            errors.append(f"Invalid target format: '{t}'. Expected URL, IP address, or CIDR notation.")

    return valid, errors


async def push_progress(scan_id: int, message: dict):
    """Push a progress message to the in-memory buffer for WebSocket delivery."""
    if scan_id not in scan_progress:
        scan_progress[scan_id] = []
    scan_progress[scan_id].append(message)


async def run_scan(scan_id: int, targets: list[str], db_url: str):
    """
    Main scan execution coroutine — runs in background.
    FR-01 through FR-09, FR-07, FR-10, FR-11, FR-12.
    """
    # Create a new DB session for this background task
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    engine = create_async_engine(db_url)
    AsyncSession = async_sessionmaker(engine, expire_on_commit=False)

    async with AsyncSession() as db:
        # Update scan status to running
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        scan.status = ScanStatus.running
        scan.started_at = datetime.utcnow()
        scan.target_count = len(targets)
        await db.commit()

        await push_progress(scan_id, {"phase": "started", "total": len(targets), "message": "Scan started"})

        completed = 0
        failed = 0

        for idx, target in enumerate(targets):
            await push_progress(scan_id, {
                "phase": "scanning",
                "target": target,
                "current": idx + 1,
                "total": len(targets),
                "pct": round((idx / len(targets)) * 100),
                "message": f"Scanning {target}...",
            })

            try:
                # Run TLS scan in thread pool to avoid blocking event loop
                loop = asyncio.get_event_loop()
                scan_result_raw = await loop.run_in_executor(
                    None,
                    lambda t=target: asyncio.run(_scan_single(t))
                )

                # Save scan result
                await save_scan_result(db, scan_id, target, scan_result_raw)
                completed += 1

                await push_progress(scan_id, {
                    "phase": "completed_target",
                    "target": target,
                    "current": idx + 1,
                    "total": len(targets),
                    "pct": round(((idx + 1) / len(targets)) * 100),
                    "label": scan_result_raw.get("pqc_label", "unknown"),
                    "message": f"Completed: {target} → {scan_result_raw.get('pqc_label', 'unknown')}",
                })

            except Exception as e:
                logger.exception(f"Error scanning {target}")
                failed += 1
                # Save failed result
                failed_result = ScanResult(
                    scan_id=scan_id,
                    target_url=target,
                    status="failed",
                    error_message=str(e),
                )
                db.add(failed_result)
                await db.commit()

                await push_progress(scan_id, {
                    "phase": "failed_target",
                    "target": target,
                    "message": f"Failed: {target} — {str(e)}",
                })

        # Recompute cyber rating
        await recompute_cyber_rating(db)

        # Mark scan complete
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = ScanStatus.completed
            scan.completed_at = datetime.utcnow()
            scan.completed_count = completed
            scan.failed_count = failed
            scan.progress_pct = 100.0
            await db.commit()

        await push_progress(scan_id, {
            "phase": "done",
            "total": len(targets),
            "completed": completed,
            "failed": failed,
            "message": f"Scan complete: {completed} succeeded, {failed} failed.",
        })


async def _scan_single(target: str) -> dict:
    """Run a full scan on one target and return enriched result dict."""
    tls_result = await tls_scanner.scan_target(target)

    # PQC classification
    pqc_result = pqc_classifier.classify(
        key_exchange=tls_result.key_exchange,
        authentication=tls_result.authentication,
        encryption=tls_result.encryption,
        hashing=tls_result.hashing,
    )

    # CBOM generation
    cipher_suites = tls_result.cipher_suites
    cbom = cbom_generator.generate_cbom(
        target_url=target,
        tls_version=tls_result.tls_version,
        cipher_suites=cipher_suites,
        cert_chain=tls_result.cert_chain,
        pqc_label=pqc_result.label,
        negotiated_cipher_info=cipher_suites[-1] if cipher_suites else None,
    )

    # Migration playbook
    playbook = playbook_generator.generate_playbook(
        target_url=target,
        tls_version=tls_result.tls_version,
        key_exchange=tls_result.key_exchange,
        authentication=tls_result.authentication,
        encryption=tls_result.encryption,
        hashing=tls_result.hashing,
        pqc_label=pqc_result.label,
    )

    return {
        "target": target,
        "success": tls_result.success,
        "error": tls_result.error,
        "tls_version": tls_result.tls_version,
        "supported_tls_versions": tls_result.supported_tls_versions,
        "negotiated_cipher": tls_result.negotiated_cipher,
        "cipher_suites": cipher_suites,
        "key_exchange": tls_result.key_exchange,
        "authentication": tls_result.authentication,
        "encryption": tls_result.encryption,
        "hashing": tls_result.hashing,
        "cert_chain": tls_result.cert_chain,
        "pqc_label": pqc_result.label,
        "pqc_details": pqc_result.details,
        "recommendations": pqc_result.recommendations,
        "cbom": cbom,
        "playbook": playbook,
    }


async def save_scan_result(db: AsyncSession, scan_id: int, target: str, data: dict):
    """Save scan result and CBOM snapshot to database."""
    cert_chain = data.get("cert_chain", [])
    cert = cert_chain[0] if cert_chain else {}

    from datetime import datetime as dt

    cert_not_before = None
    cert_not_after = None
    try:
        if cert.get("not_valid_before"):
            cert_not_before = dt.fromisoformat(cert["not_valid_before"].replace("Z", ""))
        if cert.get("not_valid_after"):
            cert_not_after = dt.fromisoformat(cert["not_valid_after"].replace("Z", ""))
    except Exception:
        pass

    scan_result = ScanResult(
        scan_id=scan_id,
        target_url=target,
        status="success" if data.get("success") else "failed",
        error_message=data.get("error"),
        tls_version=data.get("tls_version"),
        cipher_suites_json=json.dumps(data.get("cipher_suites", [])),
        negotiated_cipher=data.get("negotiated_cipher"),
        key_exchange=data.get("key_exchange"),
        authentication=data.get("authentication"),
        encryption=data.get("encryption"),
        hashing=data.get("hashing"),
        cert_chain_json=json.dumps(data.get("cert_chain", [])),
        cert_subject=cert.get("subject_name"),
        cert_issuer=cert.get("issuer_name"),
        cert_not_before=cert_not_before,
        cert_not_after=cert_not_after,
        cert_sig_algorithm=cert.get("signature_algorithm_reference"),
        cert_key_length=cert.get("key_length"),
        cert_authority=cert.get("issuer_name"),
        pqc_label=data.get("pqc_label"),
        pqc_details_json=json.dumps(data.get("pqc_details", {})),
        recommendations_json=json.dumps(data.get("recommendations", [])),
        playbook_json=json.dumps(data.get("playbook", {})),
    )
    db.add(scan_result)
    await db.flush()

    # CBOM Snapshot
    cbom_data = data.get("cbom", {})
    cbom_snap = CBOMSnapshot(
        scan_id=scan_id,
        target_url=target,
        algorithms_json=json.dumps(cbom_data.get("algorithms", [])),
        keys_json=json.dumps(cbom_data.get("keys", [])),
        protocols_json=json.dumps(cbom_data.get("protocols", [])),
        certificates_json=json.dumps(cbom_data.get("certificates", [])),
        pqc_label=data.get("pqc_label"),
        snapshot_hash=cbom_generator.compute_cbom_hash(cbom_data),
    )
    db.add(cbom_snap)

    # Upsert Asset
    existing = await db.execute(select(Asset).where(Asset.url == target))
    asset = existing.scalar_one_or_none()
    label_map = {
        "not_quantum_safe": PQCLabel.not_quantum_safe,
        "quantum_safe": PQCLabel.quantum_safe,
        "pqc_ready": PQCLabel.pqc_ready,
        "fully_quantum_safe": PQCLabel.fully_quantum_safe,
    }
    risk_map = {
        "critical": RiskLevel.critical,
        "high": RiskLevel.high,
        "medium": RiskLevel.medium,
        "low": RiskLevel.low,
    }
    from app.engine.rating_engine import get_risk_level_from_label
    risk_str = get_risk_level_from_label(data.get("pqc_label", "unknown"))

    if asset:
        asset.tls_version = data.get("tls_version")
        asset.cipher_suite = data.get("negotiated_cipher")
        asset.key_length = cert.get("key_length")
        asset.cert_expiry = cert_not_after
        asset.cert_authority = cert.get("issuer_name")
        asset.pqc_label = label_map.get(data.get("pqc_label", "unknown"), PQCLabel.unknown)
        asset.risk_level = risk_map.get(risk_str, RiskLevel.unknown)
        asset.last_scan = datetime.utcnow()
        asset.ipv4 = data.get("ipv4")
    else:
        hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
        asset = Asset(
            name=hostname,
            url=target,
            tls_version=data.get("tls_version"),
            cipher_suite=data.get("negotiated_cipher"),
            key_length=cert.get("key_length"),
            cert_expiry=cert_not_after,
            cert_authority=cert.get("issuer_name"),
            pqc_label=label_map.get(data.get("pqc_label", "unknown"), PQCLabel.unknown),
            risk_level=risk_map.get(risk_str, RiskLevel.unknown),
            last_scan=datetime.utcnow(),
        )
        db.add(asset)

    await db.flush()

    # Create/Update NameserverRecord based on real DNS enumeration
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        import socket
        from app.models.asset import NameserverRecord

        ais = socket.getaddrinfo(hostname, None)
        ips = list(set([ai[4][0] for ai in ais]))
        for ip in ips:
            record_type = "AAAA" if ":" in ip else "A"
            # check if exists
            existing_ns_query = await db.execute(
                select(NameserverRecord).where(
                    NameserverRecord.domain == hostname,
                    NameserverRecord.ip_address == (ip if record_type == "A" else None),
                    NameserverRecord.ipv6_address == (ip if record_type == "AAAA" else None)
                )
            )
            if not existing_ns_query.scalar_one_or_none():
                ns = NameserverRecord(
                    domain=hostname,
                    hostname=hostname,
                    ip_address=ip if record_type == "A" else None,
                    ipv6_address=ip if record_type == "AAAA" else None,
                    record_type=record_type,
                    asset_id=asset.id,
                    ttl=3600,
                    key_length=cert.get("key_length"),
                    cipher_suite_tls=data.get("negotiated_cipher"),
                    certificate_authority=cert.get("issuer_name")
                )
                db.add(ns)
    except Exception as e:
        logger.error(f"DNS lookup failed for {hostname}: {e}")

    await db.commit()
    logger.info(f"Saved result for {target}: {data.get('pqc_label')}")


async def recompute_cyber_rating(db: AsyncSession):
    """Recompute enterprise cyber rating from all assets and store in history."""
    from sqlalchemy import func
    result = await db.execute(select(Asset.pqc_label))
    labels = [row[0].value if row[0] else "unknown" for row in result.fetchall()]

    counts = {
        "fully_quantum_safe": labels.count("fully_quantum_safe"),
        "pqc_ready": labels.count("pqc_ready"),
        "quantum_safe": labels.count("quantum_safe"),
        "not_quantum_safe": labels.count("not_quantum_safe"),
        "unknown": labels.count("unknown"),
    }

    rating = rating_engine.compute_enterprise_score(counts)
    history = CyberRatingHistory(
        score=rating["score"],
        tier=rating["tier_name"],
        total_assets=rating["total_assets"],
        fully_quantum_safe=counts["fully_quantum_safe"],
        pqc_ready=counts["pqc_ready"],
        quantum_safe=counts["quantum_safe"],
        not_quantum_safe=counts["not_quantum_safe"],
    )
    db.add(history)
    await db.commit()
