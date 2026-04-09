"""Helpers for grouping assets and results by root domain."""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetDiscovery, DiscoveryCategory, PQCLabel
from app.models.cbom import CBOMSnapshot
from app.models.scan import ScanResult
from app.utils.domain_tools import extract_hostname, get_root_domain


def asset_summary(asset: Asset) -> dict:
    return {
        "id": asset.id,
        "name": asset.name,
        "url": asset.url,
        "hostname": extract_hostname(asset.url),
        "asset_type": asset.asset_type.value if asset.asset_type else None,
        "owner": asset.owner,
        "risk_level": asset.risk_level.value if asset.risk_level else None,
        "pqc_label": asset.pqc_label.value if asset.pqc_label else None,
        "tls_version": asset.tls_version,
        "cipher_suite": asset.cipher_suite,
        "key_length": asset.key_length,
        "cert_authority": asset.cert_authority,
        "last_scan": asset.last_scan,
        "cyber_score": asset.cyber_score,
    }


async def get_assets_for_domains(db: AsyncSession, domains: Optional[list[str]] = None) -> list[Asset]:
    result = await db.execute(select(Asset).order_by(Asset.url.asc()))
    assets = result.scalars().all()
    if not domains:
        return assets
    domain_set = {get_root_domain(domain) or domain for domain in domains if domain}
    return [asset for asset in assets if get_root_domain(asset.url) in domain_set]


async def get_latest_scan_results_by_target(db: AsyncSession, targets: list[str]) -> dict[str, ScanResult]:
    if not targets:
        return {}
    result = await db.execute(select(ScanResult).order_by(ScanResult.scanned_at.desc()))
    rows = result.scalars().all()
    latest: dict[str, ScanResult] = {}
    target_set = set(targets)
    for row in rows:
        if row.target_url in target_set and row.target_url not in latest:
            latest[row.target_url] = row
    return latest


async def get_latest_cbom_by_target(db: AsyncSession, targets: list[str]) -> dict[str, CBOMSnapshot]:
    if not targets:
        return {}
    result = await db.execute(select(CBOMSnapshot).order_by(CBOMSnapshot.created_at.desc()))
    rows = result.scalars().all()
    latest: dict[str, CBOMSnapshot] = {}
    target_set = set(targets)
    for row in rows:
        if row.target_url in target_set and row.target_url not in latest:
            latest[row.target_url] = row
    return latest


async def get_cbom_history_by_target(db: AsyncSession, targets: Optional[list[str]] = None) -> dict[str, list[CBOMSnapshot]]:
    result = await db.execute(select(CBOMSnapshot).order_by(CBOMSnapshot.created_at.desc()))
    rows = result.scalars().all()
    history: dict[str, list[CBOMSnapshot]] = defaultdict(list)
    target_set = set(targets or [])
    for row in rows:
        if target_set and row.target_url not in target_set:
            continue
        history[row.target_url].append(row)
    return dict(history)


async def list_domain_inventory(db: AsyncSession, domains: Optional[list[str]] = None) -> list[dict]:
    assets = await get_assets_for_domains(db, domains)
    grouped_assets: dict[str, list[Asset]] = defaultdict(list)
    for asset in assets:
        grouped_assets[get_root_domain(asset.url)].append(asset)

    requested_domains = {get_root_domain(domain) or domain for domain in domains if domain} if domains else set()
    latest_scans = await get_latest_scan_results_by_target(db, [asset.url for asset in assets])

    discovery_result = await db.execute(
        select(AssetDiscovery).where(AssetDiscovery.category == DiscoveryCategory.domain)
    )
    discoveries = discovery_result.scalars().all()

    dead_hosts_by_domain: dict[str, set[str]] = defaultdict(set)
    for discovery in discoveries:
        meta = json.loads(discovery.metadata_json or "{}")
        root = meta.get("root_domain") or get_root_domain(discovery.value)
        if requested_domains and root not in requested_domains:
            continue
        if meta.get("dns_status") == "dead":
            dead_hosts_by_domain[root].add(discovery.value)

    groups: list[dict] = []
    all_domains = set(grouped_assets.keys()) | set(dead_hosts_by_domain.keys()) | requested_domains
    for domain in sorted(all_domains):
        domain_assets = sorted(
            grouped_assets[domain],
            key=lambda asset: (asset.last_scan or asset.created_at or asset.url, asset.url),
            reverse=True,
        )
        summaries = [asset_summary(asset) for asset in domain_assets]
        scanned_count = 0
        live_count = 0
        inventory_dead_hosts: set[str] = set()
        latest_scan_at = None

        for asset in domain_assets:
            latest_scan = latest_scans.get(asset.url)
            asset_host = extract_hostname(asset.url)
            candidate_scan_time = getattr(latest_scan, "scanned_at", None) or asset.last_scan or asset.created_at
            if candidate_scan_time and (latest_scan_at is None or candidate_scan_time > latest_scan_at):
                latest_scan_at = candidate_scan_time

            if latest_scan:
                scanned_count += 1
                if latest_scan.status == "success":
                    live_count += 1
                elif asset_host:
                    inventory_dead_hosts.add(asset_host)
                continue

            if asset.last_scan:
                scanned_count += 1

            if asset.pqc_label in {PQCLabel.dns_failed, PQCLabel.intranet_only}:
                if asset_host:
                    inventory_dead_hosts.add(asset_host)
            elif asset.last_scan and asset.pqc_label not in {PQCLabel.unknown, None}:
                live_count += 1

        dead_hosts = sorted(dead_hosts_by_domain.get(domain, set()) | inventory_dead_hosts)
        groups.append({
            "domain": domain,
            "target_count": len(domain_assets),
            "scanned_count": scanned_count,
            "live_count": live_count,
            "dead_count": len(dead_hosts),
            "latest_scan_at": latest_scan_at,
            "targets": summaries,
            "dead_hosts": dead_hosts,
        })

    return sorted(
        groups,
        key=lambda group: (group["latest_scan_at"] is not None, group["latest_scan_at"] or group["domain"], group["domain"]),
        reverse=True,
    )
