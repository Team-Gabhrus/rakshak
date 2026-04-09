"""Targeted backend verification for the latest Rakshak feature changes.

This script uses isolated fixture data and cleans up after itself.
Run from the `rakshak/` directory:

    python scripts/verify_backend_features.py
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import delete, select

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ["DEBUG"] = "false"
logging.getLogger("httpx").setLevel(logging.WARNING)

from app.database import AsyncSessionLocal, init_db  # noqa: E402
from app.main import app, seed_default_users  # noqa: E402
from app.models.asset import (  # noqa: E402
    Asset,
    AssetDiscovery,
    AssetType,
    DiscoveryCategory,
    DiscoveryStatus,
    NameserverRecord,
    PQCLabel,
    RiskLevel,
)
from app.models.cbom import CBOMSnapshot  # noqa: E402
from app.models.chat import ChatMessage, ChatSession  # noqa: E402
from app.models.report import DeliveryChannel, Report, ReportFormat  # noqa: E402
from app.models.scan import Scan, ScanResult, ScanStatus  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services.domain_service import list_domain_inventory  # noqa: E402
from app.services.export_service import collect_report_data  # noqa: E402
from app.services.subdomain_service import (  # noqa: E402
    SubdomainScanState,
    decide_subdomain_job,
    get_active_subdomain_task_count,
    subdomain_scan_states,
)


def log_result(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    suffix = f" - {detail}" if detail else ""
    print(f"[{status}] {name}{suffix}")


def expect(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"{name} failed. {detail}".strip())
    log_result(name, True, detail)


async def cleanup_marker(marker: str) -> None:
    async with AsyncSessionLocal() as db:
        asset_rows = await db.execute(select(Asset.id).where(Asset.url.ilike(f"%{marker}%")))
        asset_ids = list(asset_rows.scalars().all())

        session_rows = await db.execute(select(ChatSession.id).where(ChatSession.title.ilike(f"%{marker}%")))
        session_ids = list(session_rows.scalars().all())
        if session_ids:
            await db.execute(delete(ChatMessage).where(ChatMessage.session_id.in_(session_ids)))
            await db.execute(delete(ChatSession).where(ChatSession.id.in_(session_ids)))

        if asset_ids:
            await db.execute(delete(CBOMSnapshot).where(CBOMSnapshot.asset_id.in_(asset_ids)))
            await db.execute(delete(ScanResult).where(ScanResult.asset_id.in_(asset_ids)))
            await db.execute(delete(NameserverRecord).where(NameserverRecord.asset_id.in_(asset_ids)))

        await db.execute(delete(CBOMSnapshot).where(CBOMSnapshot.target_url.ilike(f"%{marker}%")))
        await db.execute(delete(ScanResult).where(ScanResult.target_url.ilike(f"%{marker}%")))
        await db.execute(delete(AssetDiscovery).where(AssetDiscovery.value.ilike(f"%{marker}%")))
        await db.execute(delete(AssetDiscovery).where(AssetDiscovery.name.ilike(f"%{marker}%")))
        await db.execute(delete(NameserverRecord).where(NameserverRecord.domain.ilike(f"%{marker}%")))
        await db.execute(delete(NameserverRecord).where(NameserverRecord.hostname.ilike(f"%{marker}%")))
        await db.execute(delete(Asset).where(Asset.url.ilike(f"%{marker}%")))
        await db.execute(delete(Report).where(Report.title.ilike(f"%{marker}%")))
        await db.execute(delete(Scan).where(Scan.targets_json.ilike(f"%{marker}%")))
        await db.execute(delete(User).where(User.username.ilike(f"%{marker}%")))
        await db.execute(delete(User).where(User.email.ilike(f"%{marker}%")))
        await db.commit()


async def login_admin(client: httpx.AsyncClient) -> str:
    res = await client.post("/api/auth/login", json={"username": "admin", "password": "admin@123"})
    expect("Admin login", res.status_code == 200, f"status={res.status_code}")
    data = res.json()
    expect("Admin login bypasses OTP", data.get("require_otp") is False)
    return data["access_token"]


async def seed_fixture_data(marker: str) -> dict:
    root_domain = f"{marker}.example"
    root_url = f"https://{root_domain}"
    app_url = f"https://app.{root_domain}"
    dead_url = f"https://dead.{root_domain}"
    discovered_dead_host = f"legacy.{root_domain}"
    cleanup_host = f"cleanup.{root_domain}"
    cleanup_url = f"https://{cleanup_host}"
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    async with AsyncSessionLocal() as db:
        admin = (await db.execute(select(User).where(User.username == "admin"))).scalar_one()

        assets = [
            Asset(
                name=f"{marker}-root",
                url=root_url,
                asset_type=AssetType.web_app,
                risk_level=RiskLevel.low,
                pqc_label=PQCLabel.fully_quantum_safe,
                tls_version="TLS 1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                last_scan=now,
                owner="verification",
            ),
            Asset(
                name=f"{marker}-app",
                url=app_url,
                asset_type=AssetType.web_app,
                risk_level=RiskLevel.medium,
                pqc_label=PQCLabel.pqc_ready,
                tls_version="TLS 1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                last_scan=now,
                owner="verification",
            ),
            Asset(
                name=f"{marker}-dead",
                url=dead_url,
                asset_type=AssetType.web_app,
                risk_level=RiskLevel.unknown,
                pqc_label=PQCLabel.dns_failed,
                last_scan=now,
                owner="verification",
            ),
            Asset(
                name=f"{marker}-cleanup",
                url=cleanup_url,
                asset_type=AssetType.web_app,
                risk_level=RiskLevel.low,
                pqc_label=PQCLabel.pqc_ready,
                tls_version="TLS 1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                last_scan=now,
                owner="verification",
            ),
        ]
        db.add_all(assets)
        await db.flush()

        completed_scan = Scan(
            status=ScanStatus.completed,
            targets_json=json.dumps([root_url, app_url, dead_url]),
            target_count=3,
            completed_count=2,
            failed_count=1,
            progress_pct=100.0,
            created_by=admin.id,
            started_at=now,
            completed_at=now,
        )
        queued_scan = Scan(
            status=ScanStatus.queued,
            targets_json=json.dumps([cleanup_url]),
            target_count=1,
            completed_count=0,
            failed_count=0,
            progress_pct=0.0,
            created_by=admin.id,
            started_at=now,
        )
        cleanup_scan = Scan(
            status=ScanStatus.completed,
            targets_json=json.dumps([cleanup_url]),
            target_count=1,
            completed_count=1,
            failed_count=0,
            progress_pct=100.0,
            created_by=admin.id,
            started_at=now,
            completed_at=now,
        )
        db.add_all([completed_scan, queued_scan, cleanup_scan])
        await db.flush()

        db.add_all([
            ScanResult(
                scan_id=completed_scan.id,
                asset_id=assets[0].id,
                target_url=root_url,
                status="success",
                tls_version="TLS 1.3",
                key_exchange="ML-KEM-768",
                authentication="ML-DSA",
                encryption="AES-256-GCM",
                hashing="SHA384",
                pqc_label="fully_quantum_safe",
                recommendations_json=json.dumps(["Keep current posture"]),
                playbook_json=json.dumps({"steps": [{"title": "Monitor posture"}]}),
            ),
            ScanResult(
                scan_id=completed_scan.id,
                asset_id=assets[1].id,
                target_url=app_url,
                status="success",
                tls_version="TLS 1.3",
                key_exchange="ML-KEM-768",
                authentication="RSA",
                encryption="AES-256-GCM",
                hashing="SHA384",
                pqc_label="pqc_ready",
                recommendations_json=json.dumps(["Upgrade certificate chain"]),
                playbook_json=json.dumps({"steps": [{"title": "Replace classical CA"}]}),
            ),
            ScanResult(
                scan_id=completed_scan.id,
                asset_id=assets[2].id,
                target_url=dead_url,
                status="failed",
                error_message="dns_failed",
                pqc_label="dns_failed",
            ),
            ScanResult(
                scan_id=cleanup_scan.id,
                asset_id=assets[3].id,
                target_url=cleanup_url,
                status="success",
                tls_version="TLS 1.3",
                key_exchange="ML-KEM-768",
                authentication="ML-DSA",
                encryption="AES-256-GCM",
                hashing="SHA384",
                pqc_label="pqc_ready",
            ),
        ])

        db.add_all([
            CBOMSnapshot(
                scan_id=completed_scan.id,
                asset_id=assets[0].id,
                target_url=root_url,
                pqc_label="fully_quantum_safe",
                algorithms_json=json.dumps([{"name": "ML-KEM-768"}]),
                protocols_json=json.dumps([{"version": "TLS 1.3"}]),
                certificates_json=json.dumps([{"name": root_domain, "issuer_name": "Verification CA"}]),
                keys_json=json.dumps([{"name": "leaf", "size": "3072 bits"}]),
                snapshot_hash=f"{marker}-cbom-root",
            ),
            CBOMSnapshot(
                scan_id=completed_scan.id,
                asset_id=assets[1].id,
                target_url=app_url,
                pqc_label="pqc_ready",
                algorithms_json=json.dumps([{"name": "RSA"}]),
                protocols_json=json.dumps([{"version": "TLS 1.3"}]),
                certificates_json=json.dumps([{"name": f"app.{root_domain}", "issuer_name": "Verification CA"}]),
                keys_json=json.dumps([{"name": "leaf", "size": "2048 bits"}]),
                snapshot_hash=f"{marker}-cbom-app",
            ),
            CBOMSnapshot(
                scan_id=cleanup_scan.id,
                asset_id=assets[3].id,
                target_url=cleanup_url,
                pqc_label="pqc_ready",
                algorithms_json=json.dumps([{"name": "ML-KEM-768"}]),
                protocols_json=json.dumps([{"version": "TLS 1.3"}]),
                certificates_json=json.dumps([{"name": cleanup_host, "issuer_name": "Verification CA"}]),
                keys_json=json.dumps([{"name": "leaf", "size": "3072 bits"}]),
                snapshot_hash=f"{marker}-cbom-cleanup",
            ),
        ])

        db.add_all([
            AssetDiscovery(
                category=DiscoveryCategory.domain,
                status=DiscoveryStatus.confirmed,
                name=discovered_dead_host,
                value=discovered_dead_host,
                metadata_json=json.dumps({"root_domain": root_domain, "dns_status": "dead", "source": "verification"}),
            ),
            AssetDiscovery(
                category=DiscoveryCategory.domain,
                status=DiscoveryStatus.confirmed,
                name=cleanup_host,
                value=cleanup_host,
                metadata_json=json.dumps({"root_domain": root_domain, "dns_status": "live", "source": "verification"}),
            ),
            NameserverRecord(
                domain=cleanup_host,
                hostname=cleanup_host,
                ip_address="203.0.113.10",
                record_type="A",
                asset_id=assets[3].id,
            ),
            Report(
                title=f"{marker}-running-report",
                report_type="on_demand",
                format=ReportFormat.json,
                delivery_channel=DeliveryChannel.local,
                modules_json=json.dumps(["inventory", "cbom", "discovery"]),
                domains_json=json.dumps([root_domain]),
                status="generating",
                created_by=admin.id,
            ),
        ])

        await db.commit()

    return {
        "root_domain": root_domain,
        "root_url": root_url,
        "app_url": app_url,
        "dead_url": dead_url,
        "discovered_dead_host": discovered_dead_host,
        "cleanup_host": cleanup_host,
        "cleanup_url": cleanup_url,
    }


async def verify_script() -> None:
    marker = f"verify{int(time.time())}"
    await init_db()
    await seed_default_users()
    await cleanup_marker(marker)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            token = await login_admin(client)
            headers = {"Authorization": f"Bearer {token}"}

            res = await client.post("/api/auth/forgot-password", json={"email": f"missing-{marker}@example.com"})
            expect(
                "Forgot password rejects unknown email",
                res.status_code == 404 and res.json().get("detail") == "User does not exist.",
                f"status={res.status_code}",
            )

            fixture = await seed_fixture_data(marker)

            checkpoint_job_id = f"{marker}-checkpoint"
            checkpoint_state = SubdomainScanState(
                job_id=checkpoint_job_id,
                domain=fixture["root_domain"],
                status="waiting_confirmation",
                processed_count=1000,
                live_count=120,
                dead_count=880,
                decision_event=asyncio.Event(),
            )
            subdomain_scan_states[checkpoint_job_id] = checkpoint_state
            expect("Subdomain checkpoint counted as active", get_active_subdomain_task_count() >= 1)

            task_res = await client.get("/api/tasks/status", headers=headers)
            expect("Task status endpoint", task_res.status_code == 200)
            task_data = task_res.json()
            expect("Task status flags running work", task_data["has_running_tasks"] is True)
            expect("Task status includes queued scans", task_data["counts"]["scans"] >= 1)
            expect("Task status includes generating reports", task_data["counts"]["reports"] >= 1)
            expect("Task status includes discovery jobs", task_data["counts"]["discovery_jobs"] >= 1)

            decision_summary = await decide_subdomain_job(checkpoint_job_id, False)
            expect("Subdomain checkpoint decision stops scanning", checkpoint_state.stop_requested is True and checkpoint_state.continue_scan is False)
            expect("Subdomain checkpoint preserves processed count", decision_summary["processed_count"] == 1000)
            subdomain_scan_states.pop(checkpoint_job_id, None)

            async with AsyncSessionLocal() as db:
                domain_groups = await list_domain_inventory(db, [fixture["root_domain"]])
                expect("Domain inventory group exists", len(domain_groups) == 1)
                group = domain_groups[0]
                expect("Domain inventory target count", group["target_count"] == 4, f"targets={group['target_count']}")
                expect("Domain inventory scanned count", group["scanned_count"] == 4, f"scanned={group['scanned_count']}")
                expect("Domain inventory live count", group["live_count"] == 3, f"live={group['live_count']}")
                expect(
                    "Domain inventory dead hosts include discovery + failed asset",
                    fixture["discovered_dead_host"] in group["dead_hosts"] and f"dead.{fixture['root_domain']}" in group["dead_hosts"],
                )

                report_data = await collect_report_data(db, ["inventory", "cbom", "rating", "discovery"], domains=[fixture["root_domain"]])
                expect("Report data contains domain sections", bool(report_data.get("domains")))
                domain_section = report_data["domains"][0]
                expect("Report data is domain-wise", domain_section["domain"] == fixture["root_domain"])
                expect("Report data target count", domain_section["target_count"] == 4)
                expect("Report data live count", domain_section["live_count"] == 3)
                expect(
                    "Report data includes latest CBOM per target",
                    any(target["latest_cbom"]["algorithms"] for target in domain_section["targets"] if target["url"] in {fixture["root_url"], fixture["app_url"]}),
                )

            chat_domains_res = await client.get("/api/chat/domains", headers=headers)
            expect("Chat domains endpoint", chat_domains_res.status_code == 200)
            chat_group = next((row for row in chat_domains_res.json() if row["domain"] == fixture["root_domain"]), None)
            expect("Chat domains returns seeded domain", chat_group is not None)
            expect("Chat domains target count", chat_group["target_count"] == 4)

            domain_ctx_res = await client.get(f"/api/chat/domain-context?domain={fixture['root_domain']}", headers=headers)
            expect("Domain context endpoint", domain_ctx_res.status_code == 200)
            domain_ctx = domain_ctx_res.json()
            expect("Domain context total targets", domain_ctx["total_targets"] == 4)
            expect("Domain context scanned targets", domain_ctx["scanned_targets"] == 4)
            expect("Domain context live targets", domain_ctx["live"] == 3)

            chat_session_res = await client.post(
                "/api/chat/sessions/start",
                headers=headers,
                json={"domain": fixture["root_domain"], "title": f"{marker}-domain-chat"},
            )
            expect("Domain chat session creation", chat_session_res.status_code == 200)
            expect("Domain chat session returns session id", bool(chat_session_res.json().get("session_id")))

            cbom_res = await client.get(f"/api/cbom?domain={fixture['root_domain']}&include_unknown=false", headers=headers)
            expect("CBOM domain filter endpoint", cbom_res.status_code == 200)
            cbom_items = cbom_res.json()
            expect("CBOM returns latest snapshots only", len(cbom_items) == 3)

            create_user_res = await client.post(
                "/api/auth/register",
                headers=headers,
                json={
                    "username": f"{marker}-user",
                    "email": f"{marker}-user@example.com",
                    "password": "TempPass@123",
                    "role": "checker",
                },
            )
            expect("Admin can create user", create_user_res.status_code == 200)
            created_user = create_user_res.json()

            delete_user_res = await client.delete(f"/api/users/{created_user['id']}", headers=headers)
            expect("Admin can delete user", delete_user_res.status_code == 200)

            async with AsyncSessionLocal() as db:
                cleanup_asset = (
                    await db.execute(select(Asset).where(Asset.url == fixture["cleanup_url"]))
                ).scalar_one()
                cleanup_asset_id = cleanup_asset.id

            delete_asset_res = await client.delete(f"/api/assets/{cleanup_asset_id}", headers=headers)
            expect("Asset deletion endpoint", delete_asset_res.status_code == 200)

            async with AsyncSessionLocal() as db:
                removed_asset = (await db.execute(select(Asset).where(Asset.url == fixture["cleanup_url"]))).scalar_one_or_none()
                removed_scan_result = (await db.execute(select(ScanResult).where(ScanResult.target_url == fixture["cleanup_url"]))).scalar_one_or_none()
                removed_cbom = (await db.execute(select(CBOMSnapshot).where(CBOMSnapshot.target_url == fixture["cleanup_url"]))).scalar_one_or_none()
                removed_discovery = (await db.execute(select(AssetDiscovery).where(AssetDiscovery.value == fixture["cleanup_host"]))).scalar_one_or_none()
                removed_ns = (await db.execute(select(NameserverRecord).where(NameserverRecord.hostname == fixture["cleanup_host"]))).scalar_one_or_none()

            expect(
                "Cascade deletion removes linked records",
                all(item is None for item in [removed_asset, removed_scan_result, removed_cbom, removed_discovery, removed_ns]),
            )

        print("\nVerification completed successfully.")
    finally:
        subdomain_scan_states.pop(f"{marker}-checkpoint", None)
        await cleanup_marker(marker)


async def main() -> None:
    try:
        await verify_script()
    except Exception as exc:
        log_result("Verification run", False, str(exc))
        raise


if __name__ == "__main__":
    asyncio.run(main())
