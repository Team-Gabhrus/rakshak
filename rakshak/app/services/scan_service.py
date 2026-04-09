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
from app.utils.domain_tools import extract_hostname, normalize_target

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
            t = t.rstrip("/")
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
        
        sem = asyncio.Semaphore(50)  # FR-10: Concurrency setup (aiming up to 50)
        
        async def process_target(idx, target):
            nonlocal completed, failed
            base_pct = round((idx / len(targets)) * 100)
            step_pct = max(1, round(100 / len(targets)))

            async def sub_progress(sub_phase, detail=""):
                sub_pcts = {"resolve": 0.0, "tls": 0.15, "oqs": 0.45, "classify": 0.75, "save": 0.90}
                sub_offset = sub_pcts.get(sub_phase, 0)
                pct = min(99, base_pct + round(step_pct * sub_offset))
                icons = {"resolve": "🔍", "tls": "🔒", "oqs": "🐳", "classify": "🏷️", "save": "💾"}
                labels = {
                    "resolve": f"Resolving {target}...",
                    "tls": f"TLS handshake with {target}...",
                    "oqs": f"OQS Docker probe for {target}...",
                    "classify": f"Classifying PQC posture for {target}...",
                    "save": f"Saving results for {target}...",
                }
                await push_progress(scan_id, {
                    "phase": "scanning",
                    "sub_phase": sub_phase,
                    "target": target,
                    "current": idx + 1,
                    "total": len(targets),
                    "pct": pct,
                    "message": f"{icons.get(sub_phase,'')} {labels.get(sub_phase, detail)}",
                })

            await sub_progress("resolve")
            try:
                loop = asyncio.get_event_loop()
                async with sem:
                    await sub_progress("tls")
                    scan_result_raw = await loop.run_in_executor(
                        None,
                        lambda t=target: asyncio.run(_scan_single(t))
                    )
                return idx, target, True, scan_result_raw
            except Exception as e:
                logger.exception(f"Error scanning {target}")
                return idx, target, False, e

        tasks = [process_target(idx, target) for idx, target in enumerate(targets)]
        
        for coro in asyncio.as_completed(tasks):
            idx, target, success, result_or_err = await coro
            if success:
                try:
                    await save_scan_result(db, scan_id, target, result_or_err)
                    completed += 1
                    label = result_or_err.get("pqc_label", "unknown")
                    label_icons = {"fully_quantum_safe": "🟢", "pqc_ready": "🔵", "partially_quantum_safe": "🟡", "not_quantum_safe": "❌", "unknown": "⚪"}
                    label_display = result_or_err.get("pqc_label_display", label.replace('_', ' ').title())
                    await push_progress(scan_id, {
                        "phase": "completed_target",
                        "target": target,
                        "current": completed + failed,
                        "total": len(targets),
                        "pct": round(((completed + failed) / len(targets)) * 100),
                        "label": label,
                        "message": f"✅ {target} → {label_icons.get(label, '')} {label_display}",
                    })
                except Exception as e:
                    logger.exception(f"Error saving {target}")
                    failed += 1
            else:
                failed += 1
                failed_result = ScanResult(
                    scan_id=scan_id,
                    target_url=target,
                    status="failed",
                    error_message=str(result_or_err),
                )
                db.add(failed_result)
                await db.commit()

                await push_progress(scan_id, {
                    "phase": "failed_target",
                    "target": target,
                    "message": f"Failed: {target} — {str(result_or_err)}",
                })

            # Intermediate DB commit for progress tracking via polling API
            try:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.completed_count = completed
                    scan.failed_count = failed
                    scan.progress_pct = round(((completed + failed) / len(targets)) * 100)
                    await db.commit()
            except Exception as e:
                logger.error(f"Failed to update intermediate db progress: {e}")

        # Recompute cyber rating safely
        try:
            await recompute_cyber_rating(db)
        except Exception as e:
            logger.error(f"Failed to recompute cyber rating: {e}")

        # Mark scan complete
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.completed
                scan.completed_at = datetime.utcnow()
                scan.completed_count = completed
                scan.failed_count = failed
                scan.progress_pct = 100.0
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to mark scan as complete in DB: {e}")

        try:
            await push_progress(scan_id, {
                "phase": "done",
                "total": len(targets),
                "completed": completed,
                "failed": failed,
                "message": f"Scan complete: {completed} succeeded, {failed} failed.",
            })
        except Exception as e:
            logger.error(f"Failed to push final done progress: {e}")


async def _check_reachability(host: str, port: int, timeout: float = 5.0) -> str:
    """
    Quick pre-scan reachability check.
    Returns: 'reachable' | 'intranet_only' | 'dns_failed'
    - dns_failed:    hostname does not resolve in public DNS
    - intranet_only: DNS resolves but TCP connection to the target port times out
    - reachable:     TCP connects (proceed to full scan)
    """
    import socket
    loop = asyncio.get_event_loop()

    # 1. DNS check
    try:
        await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, port))
    except socket.gaierror:
        return "dns_failed"

    # 2. TCP check — use the target's own port so PQC servers on non-443 ports aren't penalised
    def _tcp():
        with socket.create_connection((host, port), timeout=timeout):
            pass
    try:
        await loop.run_in_executor(None, _tcp)
        return "reachable"
    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
        return "intranet_only"


async def _scan_single(target: str) -> dict:
    """Run a full scan on one target and return enriched result dict."""
    from urllib.parse import urlparse
    parsed = urlparse(target if target.startswith(("http://", "https://")) else f"https://{target}")
    host = parsed.hostname or target
    port = parsed.port or 443

    tls_result = await tls_scanner.scan_target(target)

    if not tls_result.success:
        # ── Smart failure classification ───────────────────────────────
        # Don't blindly return 'unknown' — probe DNS + TCP so we can
        # give a meaningful label (dns_failed / intranet_only / unknown).
        try:
            reach = await _check_reachability(host, port)
        except Exception:
            reach = "unknown"

        label_map_fail = {
            "dns_failed":    ("dns_failed",    "🚫 DNS Failed",
                              "Hostname has no public DNS record. This may be an internal or decommissioned service."),
            "intranet_only": ("intranet_only", "🔒 Intranet Only",
                              "Host resolves but port is firewalled. Service is likely only accessible from within the bank's network."),
            "reachable":     ("unknown",       "⚪ Unknown",
                              tls_result.error or "Scan error: TLS handshake failed despite TCP connectivity."),
        }
        pqc_label, pqc_display, err_msg = label_map_fail.get(reach, label_map_fail["reachable"])

        return {
            "target": target,
            "success": False,
            "error": err_msg,
            "tls_version": None,
            "supported_tls_versions": [],
            "negotiated_cipher": None,
            "cipher_suites": [],
            "key_exchange": None,
            "authentication": None,
            "encryption": None,
            "hashing": None,
            "cert_chain": [],
            "pqc_label": pqc_label,
            "pqc_label_display": pqc_display,
            "pqc_details": {"error": err_msg, "reachability": reach},
            "recommendations": [{"component": "Network", "action": err_msg, "priority": "Informational", "effort": "Low"}],
            "cbom": {},
            "playbook": {},
        }


    # PQC classification
    pqc_result = pqc_classifier.classify(
        key_exchange=tls_result.key_exchange,
        authentication=tls_result.authentication,
        encryption=tls_result.encryption,
        hashing=tls_result.hashing,
        cert_chain=tls_result.cert_chain,
        supported_versions=tls_result.supported_tls_versions,
        cipher_suites=tls_result.cipher_suites,
    )

    # CBOM generation
    cbom = cbom_generator.generate_cbom(
        target_url=target,
        tls_version=tls_result.tls_version,
        cipher_suites=tls_result.cipher_suites,
        cert_chain=tls_result.cert_chain,
        pqc_label=pqc_result.label,
        negotiated_cipher_info=next((cs for cs in tls_result.cipher_suites if cs.get('name') == tls_result.negotiated_cipher), None),
        version_ciphers=tls_result.version_ciphers,
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
        leaf_pqc=pqc_result.details.get("leaf_pqc", False),
        full_chain_pqc=pqc_result.details.get("cert_chain_pqc", False),
        cert_sig_algo=tls_result.cert_chain[0].get("signature_algorithm_reference") if tls_result.cert_chain else None,
        supported_versions=tls_result.supported_tls_versions,
        cipher_suites=tls_result.cipher_suites,
    )

    return {
        "target": target,
        "success": tls_result.success,
        "error": tls_result.error,
        "tls_version": tls_result.tls_version,
        "supported_tls_versions": tls_result.supported_tls_versions,
        "negotiated_cipher": tls_result.negotiated_cipher,
        "cipher_suites": tls_result.cipher_suites,
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
    normalized_target = normalize_target(target) or target.rstrip("/")
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

    # Upsert Asset
    existing = await db.execute(select(Asset).where(Asset.url == normalized_target))
    asset = existing.scalar_one_or_none()
    label_map = {
        "not_quantum_safe": PQCLabel.not_quantum_safe,
        "partially_quantum_safe": PQCLabel.partially_quantum_safe,
        "pqc_ready": PQCLabel.pqc_ready,
        "fully_quantum_safe": PQCLabel.fully_quantum_safe,
        "intranet_only": PQCLabel.intranet_only,
        "dns_failed": PQCLabel.dns_failed,
    }
    risk_map = {
        "critical": RiskLevel.critical,
        "high": RiskLevel.high,
        "medium": RiskLevel.medium,
        "low": RiskLevel.low,
    }
    from app.engine.rating_engine import get_risk_level_from_label, LABEL_SCORE
    
    pqc_label_str = data.get("pqc_label", "unknown")
    risk_str = get_risk_level_from_label(pqc_label_str)
    
    # Compute individual asset cyber score based on PQC label (FR-47 mechanics)
    cyber_score = float(LABEL_SCORE.get(pqc_label_str, 200))

    if asset:
        asset.tls_version = data.get("tls_version")
        asset.cipher_suite = data.get("negotiated_cipher")
        asset.key_length = cert.get("key_length")
        asset.cert_expiry = cert_not_after
        asset.cert_authority = cert.get("issuer_name")
        asset.pqc_label = label_map.get(pqc_label_str, PQCLabel.unknown)
        asset.risk_level = risk_map.get(risk_str, RiskLevel.unknown)
        asset.last_scan = datetime.utcnow()
        asset.ipv4 = data.get("ipv4")
        asset.cyber_score = cyber_score
    else:
        hostname = extract_hostname(normalized_target)
        asset = Asset(
            name=hostname,
            url=normalized_target,
            tls_version=data.get("tls_version"),
            cipher_suite=data.get("negotiated_cipher"),
            key_length=cert.get("key_length"),
            cert_expiry=cert_not_after,
            cert_authority=cert.get("issuer_name"),
            pqc_label=label_map.get(pqc_label_str, PQCLabel.unknown),
            risk_level=risk_map.get(risk_str, RiskLevel.unknown),
            last_scan=datetime.utcnow(),
            cyber_score=cyber_score,
        )
        db.add(asset)

    await db.flush()

    scan_result = ScanResult(
        scan_id=scan_id,
        asset_id=asset.id,
        target_url=normalized_target,
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

    # CBOM Snapshot
    cbom_data = data.get("cbom", {})
    cbom_snap = CBOMSnapshot(
        scan_id=scan_id,
        asset_id=asset.id,
        target_url=normalized_target,
        algorithms_json=json.dumps(cbom_data.get("algorithms", [])),
        keys_json=json.dumps(cbom_data.get("keys", [])),
        protocols_json=json.dumps(cbom_data.get("protocols", [])),
        certificates_json=json.dumps(cbom_data.get("certificates", [])),
        pqc_label=data.get("pqc_label"),
        snapshot_hash=cbom_generator.compute_cbom_hash(cbom_data),
    )
    db.add(cbom_snap)

    # Create/Update NameserverRecord based on real DNS enumeration
    hostname = extract_hostname(normalized_target)
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
        "partially_quantum_safe": labels.count("partially_quantum_safe"),
        "not_quantum_safe": labels.count("not_quantum_safe"),
        "unknown": labels.count("unknown"),
        "intranet_only": labels.count("intranet_only"),
        "dns_failed": labels.count("dns_failed"),
    }

    rating = rating_engine.compute_enterprise_score(counts)
    history = CyberRatingHistory(
        score=rating["score"],
        tier=rating["tier_name"],
        total_assets=rating["total_assets"],
        fully_quantum_safe=counts["fully_quantum_safe"],
        pqc_ready=counts["pqc_ready"],
        partially_quantum_safe=counts["partially_quantum_safe"],
        not_quantum_safe=counts["not_quantum_safe"],
    )
    db.add(history)
    await db.commit()
