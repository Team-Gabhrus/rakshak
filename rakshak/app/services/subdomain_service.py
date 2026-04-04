"""
Subdomain Discovery Service — passive OSINT aggregation with DNS verification.
Integrated into Rakshak's Asset Discovery pipeline.

Sources: crt.sh (Certificate Transparency), AlienVault OTX, Wayback Machine CDX.
"""
import asyncio
import json
import logging
import re
import socket
import concurrent.futures
from typing import Optional
from datetime import datetime

import requests
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import AssetDiscovery, DiscoveryCategory, DiscoveryStatus

logger = logging.getLogger(__name__)

# --- regex helpers ------------------------------------------------

def _extract_subdomains(text: str, domain: str) -> set[str]:
    """Extract all subdomains of `domain` from arbitrary text."""
    pattern = re.compile(r'([a-zA-Z0-9*._-]+)\.' + re.escape(domain))
    clean = text.replace('\\n', ' ').replace('\n', ' ')
    found = set()
    for match in pattern.findall(clean):
        sub = f"{match}.{domain}".lower().lstrip('*.')
        # filter out wildcards, CDN noise, and the bare domain
        if '*' in sub or sub == domain:
            continue
        found.add(sub)
    return found


# --- OSINT sources -----------------------------------------------

def _scrape_crtsh(domain: str, timeout: int = 30) -> set[str]:
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
        if r.status_code == 200:
            return _extract_subdomains(r.text, domain)
    except Exception as e:
        logger.warning(f"crt.sh failed for {domain}: {e}")
    return set()


def _scrape_alienvault(domain: str, timeout: int = 20) -> set[str]:
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            found = set()
            for entry in data.get("passive_dns", []):
                found |= _extract_subdomains(entry.get("hostname", ""), domain)
            return found
    except Exception as e:
        logger.warning(f"AlienVault failed for {domain}: {e}")
    return set()


def _scrape_wayback(domain: str, timeout: int = 30) -> set[str]:
    try:
        url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
               f"&output=json&collapse=urlkey&fl=original")
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            return _extract_subdomains(r.text, domain)
    except Exception as e:
        logger.warning(f"Wayback failed for {domain}: {e}")
    return set()


# --- DNS verification -------------------------------------------

def _resolve_single(host: str, timeout: float = 5.0) -> tuple[str, bool, list[str]]:
    """Resolve a hostname. Returns (host, success, ips)."""
    try:
        socket.setdefaulttimeout(timeout)
        ais = socket.getaddrinfo(host, None)
        ips = list(set(ai[4][0] for ai in ais))
        return host, True, ips
    except socket.gaierror:
        return host, False, []
    finally:
        socket.setdefaulttimeout(None)


def verify_dns(subdomains: set[str], max_workers: int = 30) -> tuple[dict, list]:
    """
    Concurrently resolve all discovered subdomains.
    Returns:
      live: {hostname: [ip, ...]}  — DNS resolves
      dead: [hostname, ...]        — DNS fails (cert ghosts / decommissioned)
    """
    live: dict[str, list[str]] = {}
    dead: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_resolve_single, h): h for h in subdomains}
        for fut in concurrent.futures.as_completed(futs):
            host, ok, ips = fut.result()
            if ok:
                live[host] = ips
            else:
                dead.append(host)

    return live, dead


# --- Main service function -------------------------------------

async def discover_subdomains(domain: str, db: AsyncSession) -> dict:
    """
    Run passive subdomain discovery for `domain`, verify DNS for each result,
    and upsert findings into the AssetDiscovery table.

    Returns a summary dict: {domain, total_found, live, dead, new_records}
    """
    logger.info(f"Starting subdomain discovery for {domain}")

    # Run all OSINT sources concurrently in a thread pool
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = [
            loop.run_in_executor(ex, _scrape_crtsh, domain),
            loop.run_in_executor(ex, _scrape_alienvault, domain),
            loop.run_in_executor(ex, _scrape_wayback, domain),
        ]
        results = await asyncio.gather(*futs, return_exceptions=True)

    all_subs: set[str] = set()
    for r in results:
        if isinstance(r, set):
            all_subs |= r

    logger.info(f"Discovered {len(all_subs)} raw subdomains for {domain}")

    # DNS verification (blocking, run in executor to not block event loop)
    live, dead = await loop.run_in_executor(None, verify_dns, all_subs)

    logger.info(f"DNS verified: {len(live)} live, {len(dead)} dead/ghost")

    # Upsert into AssetDiscovery
    new_records = 0
    now = datetime.utcnow()

    for hostname, ips in live.items():
        existing = await db.execute(
            select(AssetDiscovery).where(
                AssetDiscovery.value == hostname,
                AssetDiscovery.category == DiscoveryCategory.domain,
            )
        )
        if not existing.scalar_one_or_none():
            db.add(AssetDiscovery(
                category=DiscoveryCategory.domain,
                status=DiscoveryStatus.new,
                name=hostname,
                value=hostname,
                metadata_json=json.dumps({
                    "source": "Passive OSINT (crt.sh / AlienVault / Wayback)",
                    "dns_status": "live",
                    "ips": ips,
                    "root_domain": domain,
                    "discovered_at": now.isoformat(),
                }),
                discovered_at=now,
            ))
            new_records += 1

    for hostname in dead:
        existing = await db.execute(
            select(AssetDiscovery).where(
                AssetDiscovery.value == hostname,
                AssetDiscovery.category == DiscoveryCategory.domain,
            )
        )
        if not existing.scalar_one_or_none():
            db.add(AssetDiscovery(
                category=DiscoveryCategory.domain,
                # Auto-mark cert-ghosts as false_positive so they don't clutter the view
                status=DiscoveryStatus.false_positive,
                name=hostname,
                value=hostname,
                metadata_json=json.dumps({
                    "source": "Passive OSINT (cert ghost — DNS does not resolve)",
                    "dns_status": "dead",
                    "ips": [],
                    "root_domain": domain,
                    "discovered_at": now.isoformat(),
                }),
                discovered_at=now,
            ))
            new_records += 1

    await db.commit()
    logger.info(f"Subdomain discovery for {domain}: {new_records} new records saved")

    return {
        "domain": domain,
        "total_found": len(all_subs),
        "live": len(live),
        "dead": len(dead),
        "new_records": new_records,
        "live_hosts": sorted(live.keys()),
        "dead_hosts": sorted(dead),
    }
