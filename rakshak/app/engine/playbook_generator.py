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
) -> dict:
    """Generate FR-46 step-by-step PQC Migration Playbook tailored per asset."""

    steps = []
    effort_total = 0

    # Step 1: Inventory baseline
    steps.append({
        "step": 1,
        "title": "Establish Cryptographic Baseline",
        "description": f"Document current configuration for {target_url}: TLS {tls_version}, KX={key_exchange}, Auth={authentication}, Enc={encryption}, Hash={hashing}",
        "effort_days": 1,
        "risk": "Low",
        "tools": ["sslyze", "openssl s_client"],
    })
    effort_total += 1

    if hashing and any(h in (hashing or "") for h in ["SHA-1", "MD5"]):
        steps.append({
            "step": len(steps) + 1,
            "title": "Upgrade Hash Algorithm",
            "description": f"Replace {hashing} with SHA-384. Configure server to reject SHA-1 signatures. Re-issue any SHA-1 signed certificates.",
            "effort_days": 2,
            "risk": "Medium",
            "tools": ["openssl", "CA portal"],
        })
        effort_total += 2

    if encryption and any(e in (encryption or "") for e in ["AES-128", "3DES", "RC4"]):
        steps.append({
            "step": len(steps) + 1,
            "title": "Upgrade Encryption Algorithm",
            "description": f"Remove {encryption} from cipher suite list. Enable AES-256-GCM and ChaCha20-Poly1305. Disable weak cipher suites in server config.",
            "effort_days": 2,
            "risk": "Medium",
            "tools": ["nginx/apache config", "openssl ciphers"],
        })
        effort_total += 2

    if tls_version and tls_version in ["TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"]:
        steps.append({
            "step": len(steps) + 1,
            "title": "Disable Legacy TLS Versions",
            "description": f"Disable {tls_version} and all earlier protocols. Enable TLS 1.2 (minimum) and TLS 1.3 (preferred). Update server configuration.",
            "effort_days": 1,
            "risk": "Medium",
            "tools": ["nginx ssl_protocols directive", "apache SSLProtocol"],
        })
        effort_total += 1

    _PQC_KEX = ("ML-KEM", "MLKEM", "KYBER")
    _PQC_AUTH = ("ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA", "FALCON", "FNDSA", "DILITHIUM")

    if key_exchange and not any(key_exchange.upper().replace("-","").replace("_","").startswith(p.replace("-","")) for p in _PQC_KEX):
        steps.append({
            "step": len(steps) + 1,
            "title": "Migrate Key Exchange to ML-KEM (FIPS 203)",
            "description": f"Replace {key_exchange} key exchange with hybrid X25519+ML-KEM-768 as interim. Migrate fully to ML-KEM-768 once library support matures. Update TLS library (OpenSSL 3.x with OQS provider or liboqs).",
            "effort_days": 14,
            "risk": "High",
            "tools": ["OpenSSL 3.x + OQS provider", "liboqs", "nginx/haproxy with PQC support"],
        })
        effort_total += 14

    if authentication and not any(authentication.upper().replace("-","").replace("_","").startswith(p.replace("-","")) for p in _PQC_AUTH):
        steps.append({
            "step": len(steps) + 1,
            "title": "Migrate Certificate Authentication to ML-DSA (FIPS 204)",
            "description": f"Replace {authentication} signed certificates with ML-DSA-65 signed certificates. Request PQC certificates from a compatible CA or operate private PQC CA. Plan for hybrid classical+PQC certificates during transition.",
            "effort_days": 21,
            "risk": "High",
            "tools": ["OpenSSL 3.x + OQS", "PQC CA", "cfssl", "EJBCA"],
        })
        effort_total += 21

    steps.append({
        "step": len(steps) + 1,
        "title": "Validate & Verify Post-Migration",
        "description": "Re-scan with Rakshak after each change. Verify PQC label upgrades. Run full regression testing. Update CBOM. Document changes in asset inventory.",
        "effort_days": 3,
        "risk": "Low",
        "tools": ["Rakshak", "sslyze", "testssl.sh"],
    })
    effort_total += 3

    return {
        "target": target_url,
        "current_label": pqc_label,
        "target_label": "fully_quantum_safe",
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
    is_vulnerable_kex  = bool(key_exchange)  and not any(_norm(key_exchange).startswith(p)  for p in _PQC_KEX)
    is_vulnerable_auth = bool(authentication) and not any(_norm(authentication).startswith(p) for p in _PQC_AUTH)

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
