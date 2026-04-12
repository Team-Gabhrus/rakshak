"""
Migration Playbook Generator — FR-46
Auto-generates step-by-step PQC migration playbooks per asset.
"""
from typing import Optional


def generate_playbook(
    target_url: str,
    tls_version: Optional[str],
    key_exchange: Optional[str],
    authentication: Optional[str],
    encryption: Optional[str],
    hashing: Optional[str],
    pqc_label: str,
    leaf_pqc: bool = False,
    full_chain_pqc: bool = False,
    cert_sig_algo: Optional[str] = None,
    supported_versions: Optional[list[str]] = None,
    cipher_suites: Optional[list[dict]] = None,
) -> dict:
    """Generate FR-46 step-by-step PQC Migration Playbook tailored per asset."""

    steps = []
    migration_efforts = []

    # Step 1: Inventory baseline (Required for all)
    steps.append({
        "step": 1,
        "title": "Establish Cryptographic Baseline",
        "description": f"Document current configuration for {target_url}: TLS {tls_version}, KX={key_exchange}, Auth={authentication}, Enc={encryption or 'N/A'}, Hash={hashing or 'N/A'}",
        "effort_days": 1,
        "risk": "Low",
        "tools": ["sslyze", "openssl s_client"],
    })

    # Migration Steps (Only if not already Fully Quantum Safe)
    _PQC_KEX = ("ML-KEM", "MLKEM", "KYBER")
    _PQC_AUTH = ("ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA", "FALCON", "FNDSA", "DILITHIUM")

    # Use contains-match (not startswith) so hybrid names like X25519_MLKEM768 are recognized
    def _is_pqc(s, lst): return s and any(p.replace("-","") in str(s).upper().replace("-","").replace("_","") for p in lst)
    
    has_pqc_kex  = _is_pqc(key_exchange, _PQC_KEX)
    has_pqc_auth = _is_pqc(authentication, _PQC_AUTH)

    # 1. TLS/Cipher Suite Upgrades (Legacy Hardening)
    broken_protocols = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
    detected_broken_protos = [v for v in (supported_versions or []) if v in broken_protocols]
    if tls_version in broken_protocols:
        detected_broken_protos.append(tls_version)
    detected_broken_protos = sorted(list(set(detected_broken_protos)))

    broken_ciphers = {"3DES", "DES", "RC4", "NULL", "MD5"}
    detected_broken_ciphers = []
    for cs in (cipher_suites or []):
        name = cs.get("name", "").upper()
        if any(bc in name for bc in broken_ciphers):
            detected_broken_ciphers.append(name)
    
    if detected_broken_protos or detected_broken_ciphers:
        proto_str = ", ".join(detected_broken_protos) if detected_broken_protos else "N/A"
        cipher_str = ", ".join(detected_broken_ciphers[:5]) if detected_broken_ciphers else "N/A"
        if len(detected_broken_ciphers) > 5: cipher_str += "..."

        steps.append({
            "step": len(steps) + 1,
            "title": "Legacy Protocol/Cipher Retirement (Hardening)",
            "description": f"Disable vulnerable protocols ({proto_str}) and weak ciphers ({cipher_str}). Mandatory to prevent Downgrade Attacks and comply with NIST SP 800-52r2.",
            "effort_days": 2,
            "risk": "Medium",
            "tools": ["nginx/apache config", "sslyze", "OpenSSL"],
        })
        migration_efforts.append(2)

    # 2. Key Exchange Migration (High)
    if key_exchange and not has_pqc_kex:
        steps.append({
            "step": len(steps) + 1,
            "title": "Migrate Key Exchange to ML-KEM (FIPS 203)",
            "description": f"Replace {key_exchange} with hybrid X25519+ML-KEM-768. Update TLS libraries to support NIST FIPS 203 standards.",
            "effort_days": 14,
            "risk": "High",
            "tools": ["OpenSSL 3.x + OQS provider", "liboqs"],
        })
        migration_efforts.append(14)

    # 3. Certificate Migration (High)
    # We add this if the authentication protocol isn't PQC OR if the leaf/chain flags are false
    if (authentication and not has_pqc_auth) or not leaf_pqc or not full_chain_pqc:
        if not leaf_pqc or (authentication and not has_pqc_auth):
            steps.append({
                "step": len(steps) + 1,
                "title": "Migrate Leaf Certificate to ML-DSA (FIPS 204)",
                "description": f"Re-issue {target_url} identity certificate with ML-DSA-65 or SLH-DSA signatures to protect against CRQC impersonation.",
                "effort_days": 7,
                "risk": "High",
                "tools": ["OpenSSL 3.x + OQS", "PQC CA portal"],
            })
            migration_efforts.append(7)
        
        if not full_chain_pqc:
            steps.append({
                "step": len(steps) + 1,
                "title": "Migrate Root/Intermediate CA Chain",
                "description": "Establish a trust anchor using PQC-native CAs. Replace the entire trust path with quantum-safe signatures to ensure full chain validation.",
                "effort_days": 21,
                "risk": "High",
                "tools": ["EJBCA", "cfssl", "PQC Trust Store"],
            })
            migration_efforts.append(21)

    # Step Final: Validate & Verify (Required for all)
    steps.append({
        "step": len(steps) + 1,
        "title": "Validate & Verify Post-Migration",
        "description": "Final re-scan with Rakshak to verify PQC label upgrades and perform full regression testing.",
        "effort_days": 3,
        "risk": "Low",
        "tools": ["Rakshak", "sslyze", "testssl.sh"],
    })

    # Calculation: Baseline (1) + Max Migration Effort (Parallel work) + Validation (3)
    max_migration = max(migration_efforts) if migration_efforts else 0
    effort_total = 1 + max_migration + 3

    # Determine classification rationale
    rationale_items = []
    if pqc_label == "pqc_ready":
        if has_pqc_kex and not has_pqc_auth:
            rationale_items.append(f"✅ Key Exchange is already quantum-safe ({key_exchange})")
            rationale_items.append(f"⚠️ Certificate authentication ({authentication or 'unknown'}) is still classical")
        elif has_pqc_auth and not has_pqc_kex:
            rationale_items.append(f"✅ Certificate authentication is already quantum-safe ({authentication})")
            rationale_items.append(f"⚠️ Key Exchange ({key_exchange or 'unknown'}) is still classical")
        elif has_pqc_kex and has_pqc_auth:
            if leaf_pqc:
                rationale_items.append("✅ Key Exchange and Leaf Certificate are already quantum-safe")
            else:
                rationale_items.append(f"✅ Key Exchange is already quantum-safe ({key_exchange})")
                rationale_items.append(f"⚠️ Leaf Certificate signature ({cert_sig_algo or 'classical'}) is still classical")
            
            if not full_chain_pqc:
                rationale_items.append("⚠️ Classical Root/Intermediate CA detected — full trust chain is not yet quantum-safe")
        
        rationale_items.append("📋 To achieve Fully Quantum Safe: Complete all pending migration steps below.")

    return {
        "target": target_url,
        "current_label": pqc_label,
        "target_label": "fully_quantum_safe",
        "classification_rationale": rationale_items,
        "total_estimated_effort_days": effort_total,
        "overall_risk": "High" if effort_total > 20 else "Medium" if effort_total > 5 else "Low",
        "steps": steps,
        "references": [
            "NIST FIPS 203 — ML-KEM (Kyber): https://csrc.nist.gov/publications/detail/fips/203/final",
            "NIST FIPS 204 — ML-DSA (Dilithium): https://csrc.nist.gov/publications/detail/fips/204/final",
            "NIST FIPS 205 — SLH-DSA (SPHINCS+): https://csrc.nist.gov/publications/detail/fips/205/final",
            "CISA PQC Migration Guidance: https://www.cisa.gov/quantum",
        ],
    }


def generate_risk_timeline(key_exchange: Optional[str], authentication: Optional[str]) -> dict:
    """
    FR-45: Quantum Risk Timeline — projected vulnerability timeline.
    Based on NIST/CISA estimates for cryptanalytically relevant quantum computers (CRQC).
    """
    _PQC_KEX  = ("MLKEM", "KYBER")
    _PQC_AUTH = ("MLDSA", "SLHDSA", "SPHINCS", "FALCON", "FNDSA", "DILITHIUM")
    def _norm(s): return (s or "").upper().replace("-","").replace("_","")
    # Use contains-match so hybrid names like X25519_MLKEM768 are recognized
    is_vulnerable_kex  = bool(key_exchange)  and not any(p in _norm(key_exchange)  for p in _PQC_KEX)
    is_vulnerable_auth = bool(authentication) and not any(p in _norm(authentication) for p in _PQC_AUTH)

    timeline = {
        "hndl_exposure": {
            "risk": "Active Now",
            "description": "Harvest Now, Decrypt Later (HNDL): Adversaries may be intercepting and storing encrypted traffic today for future quantum decryption.",
            "year_range": "2024–2030",
            "severity": "critical",
        },
        "quantum_threat_estimate": {
            "description": "NIST/CISA estimate a Cryptanalytically Relevant Quantum Computer (CRQC) capable of breaking RSA/ECC could emerge within 10–15 years.",
            "year_range": "2030–2040",
            "severity": "high",
        },
        "phases": [
            {
                "phase": "Immediate (Now)",
                "year": "2024–2026",
                "action": "Inventory all cryptographic assets (CBOM). Identify HNDL-exposed data. Begin PQC library evaluation.",
                "risk_level": "high" if (is_vulnerable_kex or is_vulnerable_auth) else "low",
            },
            {
                "phase": "Short-Term",
                "year": "2026–2028",
                "action": "Deploy hybrid PQC+classical TLS for new connections. Prioritize long-lived secrets and sensitive data channels.",
                "risk_level": "critical" if (is_vulnerable_kex or is_vulnerable_auth) else "medium",
            },
            {
                "phase": "Medium-Term",
                "year": "2028–2032",
                "action": "Full migration to ML-KEM and ML-DSA across all public-facing systems. Retire classical-only cipher suites.",
                "risk_level": "critical" if (is_vulnerable_kex or is_vulnerable_auth) else "medium",
            },
            {
                "phase": "Long-Term",
                "year": "2032+",
                "action": "Operate fully quantum-safe infrastructure. Monitor NIST PQC Round 4+ for additional algorithms.",
                "risk_level": "low",
            },
        ],
        "vulnerable_kex": is_vulnerable_kex,
        "vulnerable_auth": is_vulnerable_auth,
        "current_kex": key_exchange,
        "current_auth": authentication,
    }
    return timeline
