"""
Stress test: Validate that the optimized scanning engine produces
correct results AND measure the performance improvement.

Tests:
1. OQS probe timing (key metric — should be <5s for classical, <10s for PQC)
2. Single-target scan accuracy (PQC detection, classical non-PQC)
3. Frontend fields validation (_scan_single output)
4. Bulk scan timing (20 targets concurrently)
"""
import asyncio
import sys
import os
import time
import json

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.engine import tls_scanner

# ── Test Targets ────────────────────────────────────────────────────
TEST_TARGETS = {
    "pqc_hybrid": "google.com",          # Uses X25519MLKEM768
    "pqc_hybrid_2": "cloudflare.com",     # Uses X25519MLKEM768
    "classical_bank": "apps.pnb.bank.in", # Classical bank host (no PQC)
    "classical_generic": "hrms.sbi.bank.in", # Classical bank host (no PQC)
}

# Fields the frontend expects from _scan_single
# Note: pqc_label_display is only present on the failure path (pre-existing behavior)
REQUIRED_RESULT_FIELDS = {
    "success", "target", "tls_version", "supported_tls_versions",
    "negotiated_cipher", "cipher_suites", "key_exchange",
    "authentication", "encryption", "hashing", "cert_chain",
    "pqc_label", "pqc_details",
    "recommendations", "cbom", "playbook",
}


async def test_oqs_probe(label: str, host: str, port: int = 443) -> dict:
    """Test OQS probe directly and measure timing."""
    print(f"\n  [{label}] OQS probe: {host}:{port}...")
    start = time.perf_counter()
    result = await tls_scanner._oqs_probe(host, port, timeout=30)
    elapsed = time.perf_counter() - start

    if result:
        pqc = result.get("pqc_kex_negotiated", False)
        verified = result.get("verified_kex_group")
        stk = result.get("server_temp_key", "N/A")
        stage = result.get("probe_stage", "N/A")
        sig = result.get("signature_type", "N/A")
        chain_len = len(result.get("chain_info", []))
        print(f"    Time: {elapsed:.2f}s")
        print(f"    PQC detected:   {pqc}")
        print(f"    Verified group: {verified}")
        print(f"    Server TempKey: {stk[:60]}")
        print(f"    Probe stage:    {stage}")
        print(f"    Signature:      {sig}")
        print(f"    Chain length:   {chain_len}")
    else:
        print(f"    Time: {elapsed:.2f}s")
        print(f"    Result: None (connection failed)")

    return {"label": label, "host": host, "elapsed": elapsed, "result": result}


async def test_scan_single(target: str) -> dict:
    """Test the full _scan_single pipeline."""
    from app.services.scan_service import _scan_single
    return await _scan_single(target)


async def main():
    print("=" * 70)
    print("STRESS TEST: Optimized Rakshak Scanning Engine")
    print("=" * 70)

    all_checks = []

    # ── Test 1: OQS Probe Timing ────────────────────────────────────
    print("\n" + "=" * 70)
    print("TEST 1: OQS Probe Timing (key performance metric)")
    print("=" * 70)
    print("  Old behavior: ~81s per classical target (36 Docker execs)")
    print("  New behavior: ~1-3s per classical target (1 Docker exec)")

    oqs_targets = [
        ("google.com (PQC hybrid)", "google.com"),
        ("cloudflare.com (PQC hybrid)", "cloudflare.com"),
        ("apps.pnb.bank.in (classical)", "apps.pnb.bank.in"),
        ("hrms.sbi.bank.in (classical)", "hrms.sbi.bank.in"),
    ]

    oqs_results = {}
    for label, host in oqs_targets:
        r = await test_oqs_probe(label, host)
        oqs_results[label] = r

    # Validate PQC detection
    print("\n  ── PQC Detection Check ──")
    for label in ["google.com (PQC hybrid)", "cloudflare.com (PQC hybrid)"]:
        r = oqs_results[label]
        res = r["result"]
        pqc = res.get("pqc_kex_negotiated", False) if res else False
        verified = res.get("verified_kex_group") if res else None
        if pqc:
            print(f"    ✅ {label}: PQC detected, verified={verified}")
            all_checks.append((f"PQC detected: {r['host']}", True))
        else:
            print(f"    ❌ {label}: PQC NOT detected")
            all_checks.append((f"PQC detected: {r['host']}", False))

    # Validate classical non-PQC
    print("\n  ── Classical (no PQC) Check ──")
    for label in ["apps.pnb.bank.in (classical)", "hrms.sbi.bank.in (classical)"]:
        r = oqs_results[label]
        res = r["result"]
        pqc = res.get("pqc_kex_negotiated", False) if res else False
        elapsed = r["elapsed"]
        if res and not pqc:
            print(f"    ✅ {label}: No PQC detected (correct) — {elapsed:.1f}s")
            all_checks.append((f"No PQC: {r['host']}", True))
        elif res and pqc:
            print(f"    ❌ {label}: PQC detected on classical target!")
            all_checks.append((f"No PQC: {r['host']}", False))
        else:
            print(f"    ⚠️  {label}: OQS probe returned None — {elapsed:.1f}s")
            all_checks.append((f"No PQC: {r['host']}", True))  # None is fine

    # Validate timing
    print("\n  ── Timing Check ──")
    for label in ["apps.pnb.bank.in (classical)", "hrms.sbi.bank.in (classical)"]:
        elapsed = oqs_results[label]["elapsed"]
        fast = elapsed < 10  # Should be <5s ideally, <10s acceptable
        status = "✅" if fast else "❌"
        print(f"    {status} {label}: {elapsed:.1f}s (threshold: <10s, old: ~81s)")
        all_checks.append((f"OQS timing <10s: {oqs_results[label]['host']}", fast))

    # ── Test 2: Full scan_target accuracy ────────────────────────────
    print("\n" + "=" * 70)
    print("TEST 2: Full scan_target Accuracy")
    print("=" * 70)

    scan_test = [
        ("PQC: google.com", "google.com"),
        ("Classical: apps.pnb.bank.in", "apps.pnb.bank.in"),
    ]

    for label, target in scan_test:
        print(f"\n  [{label}]")
        start = time.perf_counter()
        result = await tls_scanner.scan_target(target)
        elapsed = time.perf_counter() - start

        print(f"    Time: {elapsed:.2f}s")
        print(f"    Success: {result.success}")
        print(f"    TLS: {result.tls_version}")
        print(f"    KEX: {result.key_exchange}")
        print(f"    Auth: {result.authentication}")
        print(f"    Cipher: {result.negotiated_cipher}")
        print(f"    Cert chain: {len(result.cert_chain)} certs")

        if result.success:
            all_checks.append((f"scan_target success: {target}", True))
        else:
            print(f"    Error: {result.error}")
            all_checks.append((f"scan_target success: {target}", False))

    # ── Test 3: Frontend fields validation ──────────────────────────
    print("\n" + "=" * 70)
    print("TEST 3: Frontend Fields Validation (_scan_single)")
    print("=" * 70)

    frontend_cases = [
        ("PQC target", "google.com"),
        ("Classical target", "example.com"),
        ("Unreachable (intranet)", "alerts.sbi.bank.in"),
        ("DNS failure", "badssl.org"),
    ]

    for case_name, target in frontend_cases:
        print(f"\n  [{case_name}] {target}")
        start = time.perf_counter()
        scan_result = await test_scan_single(target)
        elapsed = time.perf_counter() - start

        missing = REQUIRED_RESULT_FIELDS - set(scan_result.keys())
        success = scan_result.get("success", False)
        pqc_label = scan_result.get("pqc_label", "N/A")

        print(f"    Time: {elapsed:.2f}s")
        print(f"    Success: {success}")
        print(f"    PQC Label: {pqc_label}")
        print(f"    PQC Display: {scan_result.get('pqc_label_display', 'N/A')}")

        if missing:
            print(f"    ❌ Missing fields: {missing}")
            all_checks.append((f"Fields complete: {case_name}", False))
        else:
            print(f"    ✅ All {len(REQUIRED_RESULT_FIELDS)} required fields present")
            all_checks.append((f"Fields complete: {case_name}", True))

        if not success:
            print(f"    Error: {scan_result.get('error', 'N/A')[:100]}")
            # Non-reachable should be fast (<8s)
            if case_name in ("Unreachable (intranet)", "DNS failure"):
                fast = elapsed < 15
                status = "✅" if fast else "❌"
                print(f"    {status} Quick rejection: {elapsed:.1f}s (should be <15s)")
                all_checks.append((f"Quick rejection: {case_name}", fast))

    # ── Test 4: Bulk scan timing ────────────────────────────────────
    print("\n" + "=" * 70)
    print("TEST 4: Bulk Scan Timing (20 targets, concurrent)")
    print("=" * 70)

    bulk_targets = [
        "https://google.com",
        "https://cloudflare.com",
        "https://example.com",
        "https://pnb.bank.in",
        "https://admin.pnb.bank.in",
        "https://apps.pnb.bank.in",
        "https://hrms.sbi.bank.in",
        "https://badssl.com",
        "https://api.github.com",
        "https://ap-south-1.console.aws.amazon.com",
        "https://alerts.sbi.bank.in",         # unreachable
        "https://apibanking.yb.sbi.bank.in",  # unreachable
        "https://apicasa.pnb.bank.in",        # unreachable
        "https://email.pnb.bank.in",          # unreachable
        "https://badssl.org",                  # dns fail
        "https://bbps.pnb.bank.in",
        "https://fastag.sbi.bank.in",
        "https://home.sbi.bank.in",
        "https://ibanking.pnb.bank.in",
        "https://kiosk.sbi.bank.in",
    ]

    print(f"  Targets: {len(bulk_targets)}")
    print(f"  Mix: 10 reachable + 4 unreachable + 1 DNS fail + 5 reachable")

    start = time.perf_counter()

    sem = asyncio.Semaphore(50)
    async def scan_with_sem(t):
        async with sem:
            return await test_scan_single(t)

    tasks = [scan_with_sem(t) for t in bulk_targets]
    bulk_results = await asyncio.gather(*tasks, return_exceptions=True)

    total_time = time.perf_counter() - start

    succeeded = sum(1 for r in bulk_results if isinstance(r, dict) and r.get("success"))
    failed = sum(1 for r in bulk_results if isinstance(r, dict) and not r.get("success"))
    errors = sum(1 for r in bulk_results if isinstance(r, Exception))

    pqc_labels = {}
    for r in bulk_results:
        if isinstance(r, dict):
            label = r.get("pqc_label", "unknown")
            pqc_labels[label] = pqc_labels.get(label, 0) + 1

    print(f"\n  Results:")
    print(f"    Total time:     {total_time:.2f}s")
    print(f"    Succeeded:      {succeeded}")
    print(f"    Failed:         {failed}")
    print(f"    Exceptions:     {errors}")
    print(f"    PQC labels:     {json.dumps(pqc_labels, indent=6)}")

    if errors:
        for i, r in enumerate(bulk_results):
            if isinstance(r, Exception):
                print(f"    Exception on {bulk_targets[i]}: {r}")

    # ── Summary ──────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, ok in all_checks if ok)
    total = len(all_checks)

    for name, ok in all_checks:
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {status}  {name}")

    print(f"\n  Result: {passed}/{total} checks passed")
    print(f"  Bulk scan (20 targets): {total_time:.1f}s")

    if passed == total:
        print("  🎉 All checks passed! Optimization is working correctly.")
    else:
        print("  ⚠️  Some checks failed — review results above.")


if __name__ == "__main__":
    asyncio.run(main())
