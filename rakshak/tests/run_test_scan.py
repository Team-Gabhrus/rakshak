#!/usr/bin/env python3
"""
Rakshak Automated Test Runner
Submits scan jobs to the running Rakshak server (localhost:8000)
and prints results with expected vs actual PQC labels.

Usage:
  1. Start Rakshak:      python run.py
  2. Start test servers: python tests/test_servers.py   (in another terminal)
  3. Run this script:    python tests/run_test_scan.py
"""
import json
import time
import sys
import urllib.request
import urllib.error

RAKSHAK_BASE = "http://localhost:8000"

# ── Targets ────────────────────────────────────────────────────────────────
LOCAL_TARGETS = [
    {"url": "https://localhost:8443", "name": "Strong TLS 1.3",        "expected": "quantum_safe"},
    {"url": "https://localhost:8444", "name": "Legacy TLS 1.0",        "expected": "not_quantum_safe"},
    {"url": "https://localhost:8445", "name": "RSA-2048 TLS 1.2",      "expected": "not_quantum_safe"},
    {"url": "https://localhost:8446", "name": "Modern ECDSA TLS 1.3",  "expected": "quantum_safe"},
]

# Public HTTPS endpoints — well-known, always up
PUBLIC_TARGETS = [
    {"url": "https://badssl.com",             "name": "BadSSL (baseline)",     "expected": "not_quantum_safe"},
    {"url": "https://tls13.cloudflare.com",   "name": "Cloudflare TLS 1.3",   "expected": "quantum_safe"},
    {"url": "https://google.com",             "name": "Google (TLS 1.3 + KT)", "expected": "quantum_safe"},
    {"url": "https://expired.badssl.com",     "name": "BadSSL Expired Cert",   "expected": "not_quantum_safe"},
    {"url": "https://sha256.badssl.com",      "name": "BadSSL SHA-256",        "expected": "quantum_safe"},
    {"url": "https://rsa2048.badssl.com",     "name": "BadSSL RSA-2048",       "expected": "not_quantum_safe"},
    {"url": "https://ecc256.badssl.com",      "name": "BadSSL ECC-256",        "expected": "quantum_safe"},
    {"url": "https://dh2048.badssl.com",      "name": "BadSSL DH-2048",        "expected": "not_quantum_safe"},
    {"url": "https://onlinesbi.sbi.co.in",   "name": "SBI Online Banking",    "expected": "not_quantum_safe"},
    {"url": "https://internetbanking.pnbindia.in", "name": "PNB Internet Banking", "expected": "not_quantum_safe"},
]


def api_call(method: str, path: str, body=None, token: str = None):
    url = f"{RAKSHAK_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        err = json.loads(e.read())
        return {"error": err}
    except Exception as e:
        return {"error": str(e)}


def login(username="admin", password="admin@123") -> str:
    print(f"🔑 Logging in as {username}...")
    resp = api_call("POST", "/api/auth/login", {"username": username, "password": password})
    if "access_token" in resp:
        print(f"   ✅ Authenticated. Role: {resp.get('role')}\n")
        return resp["access_token"]
    else:
        print(f"   ❌ Login failed: {resp}")
        sys.exit(1)


def submit_scan(targets: list, token: str) -> int:
    urls = [t["url"] for t in targets]
    resp = api_call("POST", "/api/scan", {"targets": urls}, token=token)
    if "scan_id" in resp:
        return resp["scan_id"]
    print(f"  ❌ Scan submission failed: {resp}")
    return None


def poll_scan(scan_id: int, token: str, timeout: int = 120):
    print(f"⏳ Polling scan #{scan_id}...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = api_call("GET", f"/api/scan/{scan_id}/status", token=token)
        status = resp.get("status")
        pct = resp.get("progress_pct", 0)
        print(f"   [{status}] {pct:.0f}%  — {resp.get('completed_count',0)}/{resp.get('target_count',0)} targets", end="\r")
        if status in ("completed", "failed", "cancelled"):
            print()
            return resp
        time.sleep(3)
    print(f"\n  ⚠️  Timed out waiting for scan #{scan_id}")
    return None


def print_results(scan_id: int, targets: list, token: str):
    resp = api_call("GET", f"/api/scan/{scan_id}/results", token=token)
    results = resp if isinstance(resp, list) else resp.get("results", [])

    print("\n" + "═" * 70)
    print(f"  SCAN #{scan_id} RESULTS")
    print("═" * 70)

    matched = 0
    for tgt in targets:
        r = next((x for x in results if x.get("target") == tgt["url"]), None)
        if not r:
            print(f"  ❓ {tgt['name']:40s} — no result found")
            continue

        actual   = r.get("pqc_label", "unknown")
        expected = tgt.get("expected", "?")
        tls_ver  = r.get("tls_version", "?")
        cipher   = (r.get("cipher_suite") or "?")[:35]
        key_len  = r.get("key_length", "?")
        ok       = "✅" if actual == expected else "⚠️ "
        if actual == expected:
            matched += 1

        LABEL_EMOJI = {
            "fully_quantum_safe": "🟢",
            "pqc_ready":          "🔵",
            "quantum_safe":       "🟡",
            "not_quantum_safe":   "🔴",
            "unknown":            "⚪",
        }
        print(f"\n  {ok} {tgt['name']}")
        print(f"     URL:      {tgt['url']}")
        print(f"     TLS:      {tls_ver}   Key: {key_len} bits")
        print(f"     Cipher:   {cipher}")
        print(f"     PQC:      {LABEL_EMOJI.get(actual,'?')} {actual}  (expected: {expected})")
        if actual != expected:
            print(f"     ⚠️  MISMATCH — review classifier logic")
        recs = r.get("recommendations", [])
        if recs:
            print(f"     Recs:     {recs[0].get('action', '')[:80]}")

    print("\n" + "─" * 70)
    print(f"  Score: {matched}/{len(targets)} PQC labels matched expectations")
    print("─" * 70 + "\n")


def run_test_suite(targets: list, label: str, token: str):
    print(f"\n{'━'*70}")
    print(f"  🔍 {label}")
    print(f"  {len(targets)} targets\n")

    scan_id = submit_scan(targets, token)
    if not scan_id:
        return

    print(f"  Scan #{scan_id} submitted. Waiting for completion...")
    status = poll_scan(scan_id, token)
    if not status:
        return

    print_results(scan_id, targets, token)


# ── Main ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("╔" + "═"*68 + "╗")
    print("║   Rakshak Automated Test Runner — PSB Hackathon 2026" + " "*15 + "║")
    print("╚" + "═"*68 + "╝\n")

    token = login()

    # Determine what to run
    run_local  = "--public-only" not in sys.argv
    run_public = "--local-only"  not in sys.argv

    if run_local:
        run_test_suite(LOCAL_TARGETS, "LOCAL TEST SERVERS (ports 8443–8446)", token)

    if run_public:
        run_test_suite(PUBLIC_TARGETS, "PUBLIC HTTPS ENDPOINTS (badssl.com, Google, PNB, SBI)", token)

    print("✅ All tests complete! Open http://localhost:8000/asset-inventory to view results.")
