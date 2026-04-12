"""End-to-end test of the OQS probe with Docker running locally."""
import asyncio
import sys
sys.path.insert(0, ".")

from app.engine.tls_scanner import scan_target
from app.engine.pqc_classifier import classify


async def test(hostname, port=443):
    target = f"{hostname}:{port}" if port != 443 else hostname
    print(f"\n{'='*60}")
    print(f"  SCANNING: {target}")
    print(f"{'='*60}")
    r = await scan_target(target)
    print(f"  Success:  {r.success}")
    print(f"  TLS:      {r.tls_version}")
    print(f"  Cipher:   {r.negotiated_cipher}")
    print(f"  KEX:      {r.key_exchange}")
    print(f"  Auth:     {r.authentication}")

    pqc = classify(
        r.key_exchange, r.authentication, r.encryption, r.hashing,
        r.cert_chain, r.supported_tls_versions, r.cipher_suites,
    )
    print(f"\n  PQC Label:  {pqc.label_display}")
    print(f"  KEX Status: {pqc.kex_status}")
    return pqc.label


async def main():
    r1 = await test("google.com")
    print(f"\n\n{'='*60}")
    print(f"  VERDICT: google.com → {r1}")
    if r1 in ("partially_quantum_safe", "pqc_ready"):
        print(f"  ✅ PASS — hybrid PQC detected!")
    else:
        print(f"  ❌ FAIL — expected partially_quantum_safe")
    print(f"{'='*60}")


asyncio.run(main())
