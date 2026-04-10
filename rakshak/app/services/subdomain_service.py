"""
Robust subdomain discovery with breadth-first recursion and live progress events.

Primary sources:
- crt.sh
- AlienVault OTX passive DNS
- Wayback CDX
- jldc / Anubis
- CertSpotter
- HTTP artifact scraping from discovered live hosts
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import re
import socket
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import requests
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models.asset import AssetDiscovery, DiscoveryCategory, DiscoveryStatus
from app.utils.domain_tools import dedupe_preserve_order, extract_hostname, get_root_domain

logger = logging.getLogger(__name__)


subdomain_scan_progress: dict[str, list[dict]] = {}
subdomain_scan_states: dict[str, "SubdomainScanState"] = {}


@dataclass
class SubdomainScanState:
    job_id: str
    domain: str
    status: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    processed_count: int = 0
    live_count: int = 0
    dead_count: int = 0
    raw_candidate_count: int = 0
    new_records: int = 0
    breadth_level: int = 0
    final_message: str = ""
    continue_threshold: int = 1000
    next_prompt_at: int = 1000
    discovered_candidates: set[str] = field(default_factory=set)
    expanded_hosts: set[str] = field(default_factory=set)
    live_hosts: set[str] = field(default_factory=set)
    dead_hosts: set[str] = field(default_factory=set)
    current_frontier: set[str] = field(default_factory=set)
    decision_event: Optional[asyncio.Event] = None
    continue_scan: bool = True
    stop_requested: bool = False
    auto_queue_scan_on_stop: bool = False
    queued_scan_id: Optional[int] = None
    last_message: str = ""
    pending_prompt: Optional[dict] = None

    def summary(self) -> dict:
        return {
            "job_id": self.job_id,
            "domain": self.domain,
            "status": self.status,
            "created_at": self.created_at,
            "processed_count": self.processed_count,
            "live_count": self.live_count,
            "dead_count": self.dead_count,
            "raw_candidate_count": self.raw_candidate_count,
            "new_records": self.new_records,
            "breadth_level": self.breadth_level,
            "final_message": self.final_message,
            "last_message": self.last_message,
            "stop_requested": self.stop_requested,
            "action_required": self.pending_prompt is not None,
            "pending_prompt": self.pending_prompt,
            "queued_scan_id": self.queued_scan_id,
            "live_hosts": sorted(self.live_hosts),
            "dead_hosts": sorted(self.dead_hosts),
        }


def _set_pending_prompt(
    state: SubdomainScanState,
    *,
    kind: str,
    title: str,
    message: str,
    confirm_label: str,
    decline_label: str,
    level: Optional[int] = None,
) -> dict:
    state.pending_prompt = {
        "kind": kind,
        "title": title,
        "message": message,
        "confirm_label": confirm_label,
        "decline_label": decline_label,
        "level": level,
        "created_at": datetime.utcnow().isoformat(),
    }
    state.last_message = message
    return state.pending_prompt


def _clear_pending_prompt(state: SubdomainScanState) -> None:
    state.pending_prompt = None


def _should_list_job(state: SubdomainScanState) -> bool:
    active_states = {"queued", "running", "waiting_confirmation", "stopping", "awaiting_scan_confirmation"}
    return state.status in active_states or state.pending_prompt is not None


def _build_scan_ready_prompt(state: SubdomainScanState) -> dict:
    live_count = state.live_count
    title = "Large Scan Warning" if live_count > 100 else "Start Quantum Scan"
    message = (
        f"Warning! You are about to scan {live_count} targets. Continue?"
        if live_count > 100
        else f"Discovery finished with {live_count} live target(s). Start the quantum vulnerability scan now?"
    )
    return _set_pending_prompt(
        state,
        kind="scan_ready",
        title=title,
        message=message,
        confirm_label="Start Scan",
        decline_label="Later",
    )


def _extract_subdomains(text: str, domain: str) -> set[str]:
    pattern = re.compile(r"([a-zA-Z0-9*._-]+)\." + re.escape(domain))
    clean = text.replace("\\n", " ").replace("\n", " ")
    found: set[str] = set()
    for match in pattern.findall(clean):
        sub = f"{match}.{domain}".lower().lstrip("*.")
        if "*" in sub:
            continue
        found.add(sub)
    return {host for host in found if host.endswith(domain)}


def _request_text(url: str, timeout: int = 20, headers: Optional[dict] = None) -> str:
    response = requests.get(
        url,
        timeout=timeout,
        headers=headers or {"User-Agent": "Rakshak/1.0"},
        allow_redirects=True,
    )
    if response.status_code != 200:
        return ""
    return response.text


def _scrape_crtsh(domain: str, timeout: int = 30) -> set[str]:
    try:
        text = _request_text(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
        return _extract_subdomains(text, domain)
    except Exception as exc:
        logger.warning("crt.sh failed for %s: %s", domain, exc)
    return set()


def _scrape_alienvault(domain: str, timeout: int = 20) -> set[str]:
    try:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=timeout,
            headers={"User-Agent": "Rakshak/1.0"},
        )
        if response.status_code != 200:
            return set()
        data = response.json()
        found: set[str] = set()
        for entry in data.get("passive_dns", []):
            found |= _extract_subdomains(entry.get("hostname", ""), domain)
        return found
    except Exception as exc:
        logger.warning("AlienVault failed for %s: %s", domain, exc)
    return set()


def _scrape_wayback(domain: str, timeout: int = 30) -> set[str]:
    try:
        text = _request_text(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original",
            timeout=timeout,
        )
        return _extract_subdomains(text, domain)
    except Exception as exc:
        logger.warning("Wayback failed for %s: %s", domain, exc)
    return set()


def _scrape_jldc(domain: str, timeout: int = 20) -> set[str]:
    try:
        response = requests.get(
            f"https://jldc.me/anubis/subdomains/{domain}",
            timeout=timeout,
            headers={"User-Agent": "Rakshak/1.0"},
        )
        if response.status_code != 200:
            return set()
        data = response.json()
        return {sub.lower() for sub in data if isinstance(sub, str) and sub.endswith(domain) and not sub.startswith("*")}
    except Exception as exc:
        logger.warning("jldc.me failed for %s: %s", domain, exc)
    return set()


def _scrape_certspotter(domain: str, timeout: int = 20) -> set[str]:
    try:
        response = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=timeout,
            headers={"User-Agent": "Rakshak/1.0"},
        )
        if response.status_code != 200:
            return set()
        found: set[str] = set()
        for cert in response.json():
            for dns_name in cert.get("dns_names", []):
                if isinstance(dns_name, str) and dns_name.endswith(domain) and not dns_name.startswith("*"):
                    found.add(dns_name.lower())
        return found
    except Exception as exc:
        logger.warning("CertSpotter failed for %s: %s", domain, exc)
    return set()


def _scrape_http_artifacts(host: str, domain: str, timeout: int = 10) -> set[str]:
    """Extract referenced subdomains from live hosts via headers and body content."""
    found: set[str] = set()
    targets = [f"https://{host}", f"http://{host}"]
    headers = {"User-Agent": "Rakshak/1.0"}

    for target in targets:
        try:
            response = requests.get(target, timeout=timeout, headers=headers, allow_redirects=True)
            body = response.text[:300000] if response.text else ""
            merged = "\n".join(f"{key}: {value}" for key, value in response.headers.items()) + "\n" + body
            found |= _extract_subdomains(merged, domain)
        except Exception:
            continue

    return found


def _generate_permutations(seed_hosts: set[str], domain: str) -> set[str]:
    environments = [
        "api", "auth", "admin", "beta", "cdn", "dev", "gateway", "internal", "mail",
        "mobile", "ops", "portal", "preprod", "prod", "qa", "secure", "stage",
        "staging", "test", "uat", "v1", "v2", "vpn", "www",
    ]
    permutations: set[str] = set()
    words: set[str] = set()

    for host in seed_hosts:
        if not host.endswith(domain):
            continue
        sub_part = host[: -(len(domain) + 1)] if host != domain else ""
        if not sub_part:
            continue
        parts = re.split(r"[-.]", sub_part)
        words.update(part for part in parts if part and len(part) > 2)

    for env in environments:
        permutations.add(f"{env}.{domain}")

    for word in words:
        for env in environments:
            permutations.update({
                f"{word}-{env}.{domain}",
                f"{env}-{word}.{domain}",
                f"{word}.{env}.{domain}",
                f"{env}.{word}.{domain}",
            })

    return {host for host in permutations if host.endswith(domain)}


def _resolve_single(host: str, timeout: float = 4.0) -> tuple[str, bool, list[str]]:
    try:
        socket.setdefaulttimeout(timeout)
        ais = socket.getaddrinfo(host, None)
        ips = sorted({ai[4][0] for ai in ais})
        return host, True, ips
    except socket.gaierror:
        return host, False, []
    finally:
        socket.setdefaulttimeout(None)


def verify_dns(subdomains: set[str], max_workers: int = 40) -> tuple[dict[str, list[str]], list[str]]:
    live: dict[str, list[str]] = {}
    dead: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_resolve_single, hostname): hostname for hostname in subdomains}
        for future in concurrent.futures.as_completed(futures):
            hostname, ok, ips = future.result()
            if ok:
                live[hostname] = ips
            else:
                dead.append(hostname)

    return live, dead


async def _push_progress(job_id: str, payload: dict):
    state = subdomain_scan_states.get(job_id)
    if state and payload.get("message"):
        state.last_message = payload["message"]
    subdomain_scan_progress.setdefault(job_id, []).append(payload)


def get_subdomain_job(job_id: str) -> Optional[dict]:
    state = subdomain_scan_states.get(job_id)
    return state.summary() if state else None


def get_subdomain_job_live_hosts(job_id: str) -> list[str]:
    state = subdomain_scan_states.get(job_id)
    if not state:
        return []
    return sorted(state.live_hosts)


def get_active_subdomain_task_count() -> int:
    return sum(1 for state in subdomain_scan_states.values() if _should_list_job(state))


def get_action_required_subdomain_task_count() -> int:
    return sum(1 for state in subdomain_scan_states.values() if state.pending_prompt is not None)


def list_active_subdomain_jobs() -> list[dict]:
    jobs = [state.summary() for state in subdomain_scan_states.values() if _should_list_job(state)]
    return sorted(jobs, key=lambda item: item.get("created_at", ""), reverse=True)


async def decide_subdomain_job(job_id: str, continue_scanning: bool) -> dict:
    state = subdomain_scan_states.get(job_id)
    if not state:
        raise ValueError("Subdomain discovery job not found")
    if not state.decision_event:
        raise ValueError("Subdomain discovery job is not waiting for a decision")

    _clear_pending_prompt(state)
    state.continue_scan = continue_scanning
    if not continue_scanning:
        state.stop_requested = True
    state.decision_event.set()
    return state.summary()


async def stop_subdomain_job(job_id: str) -> dict:
    state = subdomain_scan_states.get(job_id)
    if not state:
        raise ValueError("Subdomain discovery job not found")

    state.stop_requested = True
    state.continue_scan = False
    state.auto_queue_scan_on_stop = True
    _clear_pending_prompt(state)
    if state.status in {"queued", "running", "waiting_confirmation"}:
        state.status = "stopping"

    await _push_progress(job_id, {
        "phase": "termination_requested",
        "domain": state.domain,
        "processed_count": state.processed_count,
        "live_count": state.live_count,
        "dead_count": state.dead_count,
        "message": (
            f"Termination requested. Preserving {state.live_count} live and "
            f"{state.dead_count} dead results discovered so far."
        ),
    })

    if state.decision_event:
        state.decision_event.set()
    return state.summary()


def set_subdomain_job_scan_id(job_id: str, scan_id: int) -> None:
    state = subdomain_scan_states.get(job_id)
    if state:
        state.queued_scan_id = scan_id
        _clear_pending_prompt(state)
        if state.status == "awaiting_scan_confirmation":
            state.status = "completed"


async def dismiss_subdomain_job_prompt(job_id: str) -> dict:
    state = subdomain_scan_states.get(job_id)
    if not state:
        raise ValueError("Subdomain discovery job not found")
    if state.status != "awaiting_scan_confirmation" or not state.pending_prompt:
        raise ValueError("Subdomain discovery job has no dismissible prompt")

    message = f"Discovery results for {state.domain} were saved without queueing a scan."
    _clear_pending_prompt(state)
    state.status = "completed"
    state.last_message = message
    await _push_progress(job_id, {
        "phase": "scan_prompt_dismissed",
        "domain": state.domain,
        "processed_count": state.processed_count,
        "live_count": state.live_count,
        "dead_count": state.dead_count,
        "message": message,
    })
    return state.summary()


def _chunked(values: list[str], size: int) -> list[list[str]]:
    return [values[index:index + size] for index in range(0, len(values), size)]


async def _gather_root_candidates(domain: str) -> set[str]:
    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [
            loop.run_in_executor(executor, _scrape_crtsh, domain),
            loop.run_in_executor(executor, _scrape_alienvault, domain),
            loop.run_in_executor(executor, _scrape_wayback, domain),
            loop.run_in_executor(executor, _scrape_jldc, domain),
            loop.run_in_executor(executor, _scrape_certspotter, domain),
        ]
        results = await asyncio.gather(*futures, return_exceptions=True)

    found: set[str] = {domain}
    for result in results:
        if isinstance(result, set):
            found |= result
    return found


async def _gather_recursive_candidates(frontier: set[str], domain: str) -> set[str]:
    if not frontier:
        return set()

    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, max(1, len(frontier)))) as executor:
        futures = [loop.run_in_executor(executor, _scrape_http_artifacts, host, domain) for host in frontier]
        results = await asyncio.gather(*futures, return_exceptions=True)

    found: set[str] = set()
    for result in results:
        if isinstance(result, set):
            found |= result

    found |= _generate_permutations(frontier, domain)
    return found


async def _upsert_discovery_batch(
    db: AsyncSession,
    domain: str,
    live_batch: dict[str, list[str]],
    dead_batch: list[str],
) -> int:
    candidates = sorted(set(live_batch.keys()) | set(dead_batch))
    if not candidates:
        return 0

    existing_rows = await db.execute(
        select(AssetDiscovery).where(
            AssetDiscovery.category == DiscoveryCategory.domain,
            AssetDiscovery.value.in_(candidates),
        )
    )
    existing_values = {row.value for row in existing_rows.scalars().all()}
    now = datetime.utcnow()
    new_records = 0

    for hostname, ips in live_batch.items():
        if hostname in existing_values:
            continue
        db.add(AssetDiscovery(
            category=DiscoveryCategory.domain,
            status=DiscoveryStatus.new,
            name=hostname,
            value=hostname,
            metadata_json=json.dumps({
                "source": "Passive OSINT + recursive HTTP artifact discovery",
                "dns_status": "live",
                "ips": ips,
                "root_domain": domain,
                "discovered_at": now.isoformat(),
            }),
            discovered_at=now,
        ))
        new_records += 1

    for hostname in dead_batch:
        if hostname in existing_values:
            continue
        db.add(AssetDiscovery(
            category=DiscoveryCategory.domain,
            status=DiscoveryStatus.false_positive,
            name=hostname,
            value=hostname,
            metadata_json=json.dumps({
                "source": "Passive OSINT + recursive HTTP artifact discovery",
                "dns_status": "dead",
                "ips": [],
                "root_domain": domain,
                "discovered_at": now.isoformat(),
            }),
            discovered_at=now,
        ))
        new_records += 1

    if new_records:
        await db.commit()
    return new_records


async def _execute_discovery(
    domain: str,
    db: AsyncSession,
    state: Optional[SubdomainScanState] = None,
    progress_callback: Optional[Callable[[dict], Awaitable[None]]] = None,
    decision_callback: Optional[Callable[[SubdomainScanState, dict], Awaitable[bool]]] = None,
) -> dict:
    root_domain = get_root_domain(domain) or extract_hostname(domain)
    if not root_domain:
        raise ValueError("Unable to determine root domain")

    if state is None:
        state = SubdomainScanState(job_id=f"inline-{uuid.uuid4().hex}", domain=root_domain)

    state.domain = root_domain
    state.status = "running"
    state.current_frontier = {root_domain}
    state.discovered_candidates.add(root_domain)

    if progress_callback:
        await progress_callback({
            "phase": "started",
            "domain": root_domain,
            "message": f"Starting breadth-first subdomain discovery for {root_domain}",
        })

    initial_candidates = await _gather_root_candidates(root_domain)
    state.discovered_candidates |= initial_candidates
    state.raw_candidate_count = len(state.discovered_candidates)

    pending_candidates = set(initial_candidates)
    breadth_level = 0
    loop = asyncio.get_running_loop()

    while pending_candidates:
        state.breadth_level = breadth_level
        current_batch_candidates = sorted(pending_candidates - state.live_hosts - state.dead_hosts)
        if not current_batch_candidates:
            break

        new_live_for_level: set[str] = set()
        for chunk in _chunked(current_batch_candidates, 250):
            live_batch, dead_batch = await loop.run_in_executor(None, verify_dns, set(chunk), 50)
            state.live_hosts |= set(live_batch.keys())
            state.dead_hosts |= set(dead_batch)
            new_live_for_level |= set(live_batch.keys())
            state.live_count = len(state.live_hosts)
            state.dead_count = len(state.dead_hosts)
            state.processed_count = state.live_count + state.dead_count
            state.new_records += await _upsert_discovery_batch(db, root_domain, live_batch, dead_batch)

            if progress_callback:
                await progress_callback({
                    "phase": "progress",
                    "domain": root_domain,
                    "level": breadth_level,
                    "processed_count": state.processed_count,
                    "live_count": state.live_count,
                    "dead_count": state.dead_count,
                    "raw_candidate_count": state.raw_candidate_count,
                    "batch_size": len(chunk),
                    "new_live": len(live_batch),
                    "message": (
                        f"Level {breadth_level + 1}: processed {state.processed_count} "
                        f"results, {state.live_count} live, {state.dead_count} dead"
                    ),
                })

            if decision_callback and state.processed_count >= state.next_prompt_at:
                should_continue = await decision_callback(state, {
                    "phase": "continue_prompt",
                    "kind": "checkpoint",
                    "title": "Discovery Checkpoint",
                    "message": f"{state.processed_count} results found. Continue Scanning?",
                    "confirm_label": "Continue",
                    "decline_label": "Stop Here",
                })
                state.next_prompt_at += state.continue_threshold
                if not should_continue:
                    state.status = "completed"
                    state.final_message = (
                        f"Stopped at {state.processed_count} results. "
                        f"Found {state.live_count} live and {state.dead_count} dead."
                    )
                    return {
                        "domain": root_domain,
                        "total_found": state.processed_count,
                        "live": state.live_count,
                        "dead": state.dead_count,
                        "new_records": state.new_records,
                        "live_hosts": sorted(state.live_hosts),
                        "dead_hosts": sorted(state.dead_hosts),
                        "stopped_early": True,
                    }

        if state.stop_requested:
            break

        next_frontier = new_live_for_level - state.expanded_hosts
        if not next_frontier:
            break

        if decision_callback:
            should_continue = await decision_callback(state, {
                "phase": "level_prompt",
                "kind": "level_complete",
                "title": "Depth Checkpoint",
                "message": (
                    f"Domain {root_domain} scanned till Level {breadth_level + 1}. "
                    f"{state.live_count} live domains discovered. Scan deeper?"
                ),
                "confirm_label": "Scan Deeper",
                "decline_label": "Stop Here",
                "level": breadth_level + 1,
            })
            if not should_continue:
                state.status = "completed"
                state.final_message = (
                    f"Stopped at Level {breadth_level + 1}. Found {state.processed_count} results, "
                    f"{state.live_count} live and {state.dead_count} dead."
                )
                return {
                    "domain": root_domain,
                    "total_found": state.processed_count,
                    "live": state.live_count,
                    "dead": state.dead_count,
                    "new_records": state.new_records,
                    "live_hosts": sorted(state.live_hosts),
                    "dead_hosts": sorted(state.dead_hosts),
                    "stopped_early": True,
                }

        state.expanded_hosts |= next_frontier
        recursive_candidates = await _gather_recursive_candidates(next_frontier, root_domain)
        recursive_candidates = {
            hostname for hostname in recursive_candidates
            if hostname not in state.discovered_candidates and hostname.endswith(root_domain)
        }
        state.discovered_candidates |= recursive_candidates
        state.raw_candidate_count = len(state.discovered_candidates)
        pending_candidates = recursive_candidates
        breadth_level += 1

        if progress_callback and recursive_candidates:
            await progress_callback({
                "phase": "breadth_shift",
                "domain": root_domain,
                "level": breadth_level,
                "frontier_size": len(next_frontier),
                "candidate_count": len(recursive_candidates),
                "message": (
                    f"Expanding breadth-first level {breadth_level + 1} from "
                    f"{len(next_frontier)} live hosts"
                ),
            })

    state.status = "completed"
    state.final_message = (
        f"Discovery stopped. Found {state.processed_count} results, "
        f"{state.live_count} live and {state.dead_count} dead."
        if state.stop_requested
        else f"Discovery complete. Found {state.processed_count} results, "
        f"{state.live_count} live and {state.dead_count} dead."
    )
    return {
        "domain": root_domain,
        "total_found": state.processed_count,
        "live": state.live_count,
        "dead": state.dead_count,
        "new_records": state.new_records,
        "live_hosts": sorted(state.live_hosts),
        "dead_hosts": sorted(state.dead_hosts),
        "stopped_early": False,
    }


async def discover_subdomains(domain: str, db: AsyncSession, pending_targets: list[str] = None) -> dict:
    """
    Backward-compatible inline discovery helper used by existing code paths.
    `pending_targets` is ignored in the new breadth-first engine because the
    WebSocket job flow now owns continuation state.
    """
    if pending_targets:
        logger.info("Ignoring deprecated pending_targets flow for %s", domain)
    return await _execute_discovery(domain, db)


async def _run_discovery_job(job_id: str, db_url: str):
    state = subdomain_scan_states[job_id]
    engine = create_async_engine(db_url)
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def progress_callback(payload: dict):
        await _push_progress(job_id, payload)

    async def decision_callback(current_state: SubdomainScanState, prompt: dict) -> bool:
        current_state.status = "waiting_confirmation"
        current_state.decision_event = asyncio.Event()
        prompt_payload = _set_pending_prompt(
            current_state,
            kind=prompt.get("kind", "checkpoint"),
            title=prompt.get("title", "Discovery Checkpoint"),
            message=prompt.get("message", "Continue Scanning?"),
            confirm_label=prompt.get("confirm_label", "Continue"),
            decline_label=prompt.get("decline_label", "Decline"),
            level=prompt.get("level"),
        )
        await _push_progress(job_id, {
            "phase": prompt.get("phase", "continue_prompt"),
            "domain": current_state.domain,
            "processed_count": current_state.processed_count,
            "live_count": current_state.live_count,
            "dead_count": current_state.dead_count,
            "level": prompt.get("level"),
            "prompt": prompt_payload,
            "message": prompt_payload["message"],
        })
        await current_state.decision_event.wait()
        current_state.decision_event = None
        if current_state.stop_requested:
            return False
        _clear_pending_prompt(current_state)
        current_state.status = "running"
        await _push_progress(job_id, {
            "phase": "resumed",
            "domain": current_state.domain,
            "message": "Continuing breadth-first discovery",
        })
        return current_state.continue_scan

    try:
        async with SessionLocal() as db:
            result = await _execute_discovery(
                state.domain,
                db,
                state=state,
                progress_callback=progress_callback,
                decision_callback=decision_callback,
            )
        if state.live_count > 0 and not state.queued_scan_id and not state.auto_queue_scan_on_stop:
            state.status = "awaiting_scan_confirmation"
            prompt_payload = _build_scan_ready_prompt(state)
            await _push_progress(job_id, {
                "phase": "scan_prompt",
                "domain": state.domain,
                "processed_count": state.processed_count,
                "live_count": state.live_count,
                "dead_count": state.dead_count,
                "new_records": state.new_records,
                "prompt": prompt_payload,
                "message": prompt_payload["message"],
            })
        else:
            state.status = "completed"
            await _push_progress(job_id, {
                "phase": "completed",
                "domain": state.domain,
                "processed_count": state.processed_count,
                "live_count": state.live_count,
                "dead_count": state.dead_count,
                "new_records": state.new_records,
                "message": state.final_message or (
                    f"Discovery complete. Found {result['total_found']} total and {result['live']} live."
                ),
            })
    except Exception as exc:
        logger.exception("Subdomain discovery job failed for %s", state.domain)
        state.status = "failed"
        state.final_message = str(exc)
        await _push_progress(job_id, {
            "phase": "failed",
            "domain": state.domain,
            "message": f"Subdomain discovery failed: {exc}",
        })
    finally:
        await engine.dispose()


async def create_subdomain_discovery_job(domain: str, db_url: str) -> dict:
    root_domain = get_root_domain(domain) or extract_hostname(domain)
    if not root_domain:
        raise ValueError("A valid root domain is required")

    job_id = uuid.uuid4().hex
    state = SubdomainScanState(job_id=job_id, domain=root_domain)
    subdomain_scan_states[job_id] = state
    subdomain_scan_progress[job_id] = []
    asyncio.create_task(_run_discovery_job(job_id, db_url))
    return {
        "job_id": job_id,
        "domain": root_domain,
        "status": state.status,
        "websocket_url": f"/ws/subdomain/{job_id}",
    }
