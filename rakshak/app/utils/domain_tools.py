"""Domain and target normalization helpers shared across modules."""
from __future__ import annotations

from urllib.parse import urlparse


TWO_PART_TLD_PREFIXES = {
    "co",
    "com",
    "gov",
    "org",
    "edu",
    "ac",
    "bank",
    "net",
    "res",
    "mod",
}


def strip_scheme(value: str | None) -> str:
    if not value:
        return ""
    return value.split("://", 1)[-1]


def extract_hostname(value: str | None) -> str:
    """Return the bare lowercase hostname for a URL/host-like string."""
    if not value:
        return ""

    candidate = value.strip()
    if not candidate:
        return ""

    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    hostname = parsed.hostname or parsed.netloc or parsed.path
    return hostname.split(":", 1)[0].strip(".").lower()


def normalize_target(value: str | None) -> str:
    """Normalize a target into an https URL when possible."""
    if not value:
        return ""

    candidate = value.strip().rstrip("/")
    if not candidate:
        return ""

    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    hostname = parsed.hostname or parsed.netloc or parsed.path
    hostname = hostname.strip("/")
    if not hostname:
        return ""

    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path.rstrip("/") if parsed.path not in ("", "/") else ""
    if parsed.query:
        path = f"{path}?{parsed.query}" if path else f"?{parsed.query}"
    return f"{parsed.scheme or 'https'}://{hostname.split(':', 1)[0]}{port}{path}".rstrip("/")


def is_two_part_tld(parts: list[str]) -> bool:
    if len(parts) < 2:
        return False
    return parts[-2] in TWO_PART_TLD_PREFIXES and len(parts[-1]) <= 3


def get_root_domain(value: str | None) -> str:
    hostname = extract_hostname(value)
    if not hostname:
        return ""

    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    if is_two_part_tld(parts):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def build_target_variants(value: str | None) -> set[str]:
    """Build URL/hostname variants used for cross-table matching."""
    hostname = extract_hostname(value)
    if not hostname:
        return set()

    return {
        hostname,
        f"http://{hostname}",
        f"https://{hostname}",
        normalize_target(hostname),
        normalize_target(f"http://{hostname}"),
        normalize_target(f"https://{hostname}"),
    }


def belongs_to_domain(value: str | None, domain: str | None) -> bool:
    hostname = extract_hostname(value)
    root_domain = get_root_domain(domain)
    if not hostname or not root_domain:
        return False
    return hostname == root_domain or hostname.endswith(f".{root_domain}")


def dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered

