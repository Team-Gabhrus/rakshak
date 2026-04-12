"""Verify the hybrid PQC KEX fix against live targets."""
import asyncio
import json
import sys
sys.path.insert(0, ".")

from app.engine.tls_scanner import scan_target
from app.engine.pqc_classifier import classify


async def test_target(hostname):
    print(f"\n{'='*60}")
    print(f"  SCANNING: {hostname}")
    print(f"{'='*60}")
    r = await scan_target(hostname)
    print(f"  Success:     {r.success}")
    print(f"  Error:       {r.error}")
    print(f"  TLS:         {r.tls_version}")
    print(f"  Cipher:      {r.negotiated_cipher}")
    print(f"  KEX:         {r.key_exchange}")
    print(f"  Auth:        {r.authentication}")
    print(f"  Enc:         {r.encryption}")
    print(f"  Hash:        {r.hashing}")
    print(f"  Versions:    {r.supported_tls_versions}")

    print(f"\n  Cert Chain:")
    for i, c in enumerate(r.cert_chain):
        name = c.get("name", "?")
        sig = c.get("signature_algorithm_reference", "?")
        print(f"    [{i}] {name}")
        print(f"        sig = {sig}")

    pqc = classify(
        r.key_exchange, r.authentication, r.encryption, r.hashing,
        r.cert_chain, r.supported_tls_versions, r.cipher_suites,
    )

    print(f"\n  PQC CLASSIFICATION:")
    print(f"    Label:      {pqc.label}")
    print(f"    Display:    {pqc.label_display}")
    print(f"    KEX Status: {pqc.kex_status}")
    print(f"    Auth Status:{pqc.auth_status}")
    print(f"    Enc Status: {pqc.enc_status}")
    print(f"    Hash Status:{pqc.hash_status}")
    print(f"    Risk:       {pqc.risk_level}")
    print(f"    Score:      {pqc.score_contribution}")
    print(f"    Leaf PQC:   {pqc.details.get('leaf_pqc')}")
    print(f"    Chain PQC:  {pqc.details.get('cert_chain_pqc')}")

    return r, pqc


async def main():
    # Test the main target the user asked about
    r1, p1 = await test_target("support.google.com")

    print(f"\n\n{'='*60}")
    print(f"  VERDICT")
    print(f"{'='*60}")
    if p1.kex_status == "pqc":
        print(f"  ✅ KEX detected as PQC: {r1.key_exchange}")
    else:
        print(f"  ❌ KEX NOT detected as PQC: {r1.key_exchange} -> {p1.kex_status}")
        print(f"     (This is expected if Docker/OQS is not available on this machine)")

    if p1.label in ("partially_quantum_safe", "pqc_ready", "fully_quantum_safe"):
        print(f"  ✅ Label upgraded: {p1.label_display}")
    else:
        print(f"  ⚠️  Label still: {p1.label_display}")
        if r1.key_exchange in (None, "ECDHE", "Unknown"):
            print(f"     Root cause: sslyze negotiated classical KEX='{r1.key_exchange}'")
            print(f"     OQS Docker probe needed to detect hybrid X25519_MLKEM768")
            print(f"     (Docker may not be available on this machine)")

asyncio.run(main())
