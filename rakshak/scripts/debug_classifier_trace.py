"""
Debug Script 3: Trace the PQC classifier decision tree step by step.
Shows exactly why a given target gets a specific label.

Usage:
    python scripts/debug_classifier_trace.py support.google.com
"""
import sys
import json
from urllib.parse import urlparse

sys.path.insert(0, ".")

from app.engine.pqc_classifier import (
    classify,
    classify_key_exchange,
    classify_authentication,
    classify_encryption,
    classify_hashing,
    PQC_KEY_EXCHANGE,
    PQC_AUTHENTICATION,
    CLASSICAL_KX_VULNERABLE,
    CLASSICAL_AUTH_VULNERABLE,
    QUANTUM_SAFE_SYMMETRIC,
    NOT_SAFE_SYMMETRIC,
)


def trace_classification(kex, auth, enc, hsh, cert_chain=None, supported_versions=None, cipher_suites=None):
    """Walk through the classifier step by step with verbose output."""
    print(f"\n{'='*70}")
    print(f"  PQC CLASSIFIER TRACE")
    print(f"{'='*70}")
    print(f"\n  INPUT:")
    print(f"    KEX:    '{kex}'")
    print(f"    Auth:   '{auth}'")
    print(f"    Enc:    '{enc}'")
    print(f"    Hash:   '{hsh}'")
    print(f"    Chain:  {len(cert_chain or [])} certs")
    print(f"    Versions: {supported_versions}")

    # Step 1: KEX classification
    print(f"\n  STEP 1: KEY EXCHANGE CLASSIFICATION")
    kex_upper = (kex or "").upper().replace("-", "_").replace(" ", "_")
    print(f"    Input normalized: '{kex_upper}'")
    print(f"    Checking against PQC_KEY_EXCHANGE: {PQC_KEY_EXCHANGE}")
    kex_status = classify_key_exchange(kex or "Unknown")
    matched_pqc = None
    for p in PQC_KEY_EXCHANGE:
        if p.upper().replace("-", "_") in kex_upper:
            matched_pqc = p
            break
    if matched_pqc:
        print(f"    ✓ Matched PQC: '{matched_pqc}' found in '{kex_upper}'")
    else:
        print(f"    ✗ No PQC match.")
        matched_vuln = None
        for v in CLASSICAL_KX_VULNERABLE:
            if v.upper() in kex_upper:
                matched_vuln = v
                break
        if matched_vuln:
            print(f"    ✗ Matched classical VULNERABLE: '{matched_vuln}' found in '{kex_upper}'")
        else:
            print(f"    ? No match at all -> 'unknown'")
    print(f"    → kex_status = '{kex_status}'")

    # Step 2: Auth classification
    print(f"\n  STEP 2: AUTHENTICATION CLASSIFICATION")
    auth_upper = (auth or "").upper().replace("-", "_").replace(" ", "_")
    print(f"    Input normalized: '{auth_upper}'")
    auth_status = classify_authentication(auth or "Unknown")
    print(f"    → auth_status = '{auth_status}'")

    # Step 3: Enc classification
    print(f"\n  STEP 3: ENCRYPTION CLASSIFICATION")
    enc_status = classify_encryption(enc or "Unknown")
    print(f"    → enc_status = '{enc_status}'")

    # Step 4: Hash classification
    print(f"\n  STEP 4: HASH CLASSIFICATION")
    hash_status = classify_hashing(hsh or "Unknown")
    print(f"    → hash_status = '{hash_status}'")

    # Step 5: Cert chain PQC check
    print(f"\n  STEP 5: CERT CHAIN PQC CHECK")
    for i, cert in enumerate(cert_chain or []):
        sig_ref = cert.get("signature_algorithm_reference", "")
        sig_upper = sig_ref.upper()
        has_pqc = any(frag in sig_upper for frag in {"ML-DSA", "SLH-DSA", "DILITHIUM", "SPHINCS", "FALCON", "FN-DSA"})
        print(f"    [{i}] sig_ref='{sig_ref}' → PQC={'YES' if has_pqc else 'NO'}")
    
    # Step 6: HNDL Decision tree
    print(f"\n  STEP 6: HNDL DECISION TREE")
    any_pqc_kex = kex_status == "pqc"
    any_pqc_auth = auth_status == "pqc"
    print(f"    any_pqc_kex = {any_pqc_kex}")
    print(f"    any_pqc_auth = {any_pqc_auth}")

    if any_pqc_kex and any_pqc_auth:
        print(f"    → Both PQC: checking full chain...")
        # would check full_chain_pqc
    elif any_pqc_kex or any_pqc_auth:
        print(f"    → Only one PQC: 'partially_quantum_safe'")
    else:
        print(f"    → Neither PQC: 'not_quantum_safe'")

    # Step 7: Downgrade check
    print(f"\n  STEP 7: DOWNGRADE VULNERABILITY CHECK")
    broken_protocols = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
    has_broken = any(v in broken_protocols for v in (supported_versions or []))
    print(f"    Supported versions: {supported_versions}")
    print(f"    Has legacy protocol: {has_broken}")

    # Final result
    print(f"\n  RUNNING ACTUAL CLASSIFIER...")
    result = classify(kex, auth, enc, hsh, cert_chain, supported_versions, cipher_suites)
    print(f"\n  FINAL RESULT:")
    print(f"    Label:      {result.label}")
    print(f"    Display:    {result.label_display}")
    print(f"    KEX:        {result.kex_status}")
    print(f"    Auth:       {result.auth_status}")
    print(f"    Risk:       {result.risk_level}")
    print(f"    Score:      {result.score_contribution}")

    return result


def demo_what_chrome_sees():
    """Show what the classifier WOULD output if we had Chrome's data."""
    print(f"\n{'='*70}")
    print(f"  HYPOTHETICAL: What if Rakshak saw what Chrome sees?")
    print(f"{'='*70}")

    # Scenario 1: What Chrome sees — hybrid KEX, classical cert
    print(f"\n  Scenario A: Chrome's actual negotiation data")
    trace_classification(
        kex="X25519_MLKEM768",           # What Chrome negotiates
        auth="ECDSA",                     # What the cert uses
        enc="AES-256-GCM",
        hsh="SHA-256",
        cert_chain=[
            {
                "name": "support.google.com",
                "signature_algorithm_reference": "ecdsa-with-SHA256 (1.2.840.10045.4.3.2)",
                "key_algorithm": "ECDSA (secp256r1)",
                "key_length": 256,
            },
            {
                "name": "GTS CA 1C3",
                "signature_algorithm_reference": "sha256WithRSAEncryption (1.2.840.113549.1.1.11)",
                "key_algorithm": "RSA",
                "key_length": 2048,
            },
        ],
    )

    # Scenario 2: What Rakshak/sslyze actually sees
    print(f"\n  Scenario B: What Rakshak/sslyze actually negotiates")
    trace_classification(
        kex="ECDHE",                      # sslyze can't do ML-KEM
        auth="ECDSA",
        enc="AES-256-GCM",
        hsh="SHA-384",
        cert_chain=[
            {
                "name": "support.google.com",
                "signature_algorithm_reference": "ecdsa-with-SHA256 (1.2.840.10045.4.3.2)",
                "key_algorithm": "ECDSA (secp256r1)",
                "key_length": 256,
            },
        ],
    )

    # Note the BIG finding
    print(f"\n  KEY INSIGHT:")
    print(f"  ────────────")
    print(f"  Even with Chrome's data (X25519_MLKEM768), the classifier SHOULD")
    print(f"  detect PQC KEX because 'MLKEM768' matches 'ML-KEM-768' in the")
    print(f"  PQC_KEY_EXCHANGE set. BUT the classifier normalize step:")
    print(f"    kex_upper = 'X25519_MLKEM768'")
    print(f"    Looking for: 'ML_KEM_768' in 'X25519_MLKEM768'")
    kex_test = "X25519_MLKEM768".upper().replace("-", "_").replace(" ", "_")
    for p in PQC_KEY_EXCHANGE:
        p_norm = p.upper().replace("-", "_")
        found = p_norm in kex_test
        print(f"    '{p_norm}' in '{kex_test}' = {found}")

    print(f"\n  Even IF sslyze could detect the hybrid KEX, the label would be:")
    print(f"  'partially_quantum_safe' because the cert chain uses ECDSA (classical).")
    print(f"  Google does NOT issue PQC certs yet. No CA does for public web PKI.")


if __name__ == "__main__":
    demo_what_chrome_sees()
