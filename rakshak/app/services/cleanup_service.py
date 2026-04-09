"""Cross-module cleanup helpers for asset/discovery deletion workflows."""
from __future__ import annotations

import json
from collections import defaultdict

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetDiscovery, NameserverRecord
from app.models.cbom import CBOMSnapshot
from app.models.chat import ChatMessage, ChatSession
from app.models.scan import Scan, ScanResult
from app.utils.domain_tools import extract_hostname


def _matches_host(value: str | None, hosts: set[str]) -> bool:
    hostname = extract_hostname(value)
    return bool(hostname and hostname in hosts)


async def _reconcile_scans(db: AsyncSession, affected_scan_ids: set[int]):
    if not affected_scan_ids:
        return

    for scan_id in affected_scan_ids:
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            continue

        result_rows = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
        rows = result_rows.scalars().all()
        if not rows:
            await db.delete(scan)
            continue

        targets = json.loads(scan.targets_json or "[]")
        remaining_targets = [target for target in targets if any(r.target_url == target for r in rows)]
        scan.targets_json = json.dumps(remaining_targets)
        scan.target_count = len(remaining_targets)
        scan.completed_count = sum(1 for row in rows if row.status == "success")
        scan.failed_count = sum(1 for row in rows if row.status != "success")
        total_done = scan.completed_count + scan.failed_count
        scan.progress_pct = round((total_done / scan.target_count) * 100, 2) if scan.target_count else 100.0


async def delete_related_records_for_hosts(db: AsyncSession, hosts: set[str]) -> dict:
    """
    Delete assets and linked records for a set of hostnames.
    Returns counts of removed records by table.
    """
    normalized_hosts = {host.lower() for host in hosts if host}
    if not normalized_hosts:
        return {"deleted_hosts": 0}

    deleted = defaultdict(int)
    affected_scan_ids: set[int] = set()

    asset_rows = await db.execute(select(Asset))
    assets = [asset for asset in asset_rows.scalars().all() if _matches_host(asset.url, normalized_hosts)]
    asset_ids = {asset.id for asset in assets}

    if asset_ids:
        chat_session_rows = await db.execute(select(ChatSession.id).where(ChatSession.asset_id.in_(asset_ids)))
        chat_session_ids = set(chat_session_rows.scalars().all())
        if chat_session_ids:
            msg_delete = await db.execute(delete(ChatMessage).where(ChatMessage.session_id.in_(chat_session_ids)))
            deleted["chat_messages"] += msg_delete.rowcount or 0
            sess_delete = await db.execute(delete(ChatSession).where(ChatSession.id.in_(chat_session_ids)))
            deleted["chat_sessions"] += sess_delete.rowcount or 0

    scan_result_rows = await db.execute(select(ScanResult))
    scan_results = [
        row for row in scan_result_rows.scalars().all()
        if _matches_host(row.target_url, normalized_hosts) or (row.asset_id in asset_ids if row.asset_id else False)
    ]
    if scan_results:
        affected_scan_ids = {row.scan_id for row in scan_results}
        scan_result_ids = [row.id for row in scan_results]
        result_delete = await db.execute(delete(ScanResult).where(ScanResult.id.in_(scan_result_ids)))
        deleted["scan_results"] += result_delete.rowcount or 0

    cbom_rows = await db.execute(select(CBOMSnapshot))
    cbom_snapshots = [
        row for row in cbom_rows.scalars().all()
        if _matches_host(row.target_url, normalized_hosts) or (row.asset_id in asset_ids if row.asset_id else False)
    ]
    if cbom_snapshots:
        cbom_ids = [row.id for row in cbom_snapshots]
        cbom_delete = await db.execute(delete(CBOMSnapshot).where(CBOMSnapshot.id.in_(cbom_ids)))
        deleted["cbom_snapshots"] += cbom_delete.rowcount or 0

    discovery_rows = await db.execute(select(AssetDiscovery))
    discovery_items = [
        row for row in discovery_rows.scalars().all()
        if _matches_host(row.value, normalized_hosts) or _matches_host(row.name, normalized_hosts)
    ]
    if discovery_items:
        discovery_ids = [row.id for row in discovery_items]
        discovery_delete = await db.execute(delete(AssetDiscovery).where(AssetDiscovery.id.in_(discovery_ids)))
        deleted["asset_discoveries"] += discovery_delete.rowcount or 0

    nameserver_rows = await db.execute(select(NameserverRecord))
    nameservers = [
        row for row in nameserver_rows.scalars().all()
        if row.domain in normalized_hosts or row.hostname in normalized_hosts or row.asset_id in asset_ids
    ]
    if nameservers:
        nameserver_ids = [row.id for row in nameservers]
        nameserver_delete = await db.execute(delete(NameserverRecord).where(NameserverRecord.id.in_(nameserver_ids)))
        deleted["nameserver_records"] += nameserver_delete.rowcount or 0

    if assets:
        asset_delete = await db.execute(delete(Asset).where(Asset.id.in_([asset.id for asset in assets])))
        deleted["assets"] += asset_delete.rowcount or 0

    await _reconcile_scans(db, affected_scan_ids)
    await db.commit()

    deleted["deleted_hosts"] = len(normalized_hosts)
    return dict(deleted)
