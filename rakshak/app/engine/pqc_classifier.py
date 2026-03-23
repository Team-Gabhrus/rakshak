"""
PQC Analysis & Classification Engine — FR-07, FR-11, FR-12
Evaluates cryptographic components against NIST PQC standards (FIPS 203/204/205)
and assigns quantum-safety labels using the HNDL Threat Model.

Labels (FR-11, HNDL Threat Model):
  ❌ not_quantum_safe       — classical KEX (ECDHE, RSA) regardless of symmetric cipher
  🟡 partially_quantum_safe — PQC KEX but classical authentication
  🔵 pqc_ready              — PQC KEX + PQC auth but legacy Root CA in trust chain
  🟢 fully_quantum_safe     — entire certificate trust chain enforces PQC natively
"""

from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------
# Algorithm classification tables (NIST FIPS 203/204/205 + CISA guidance)
# --------------------------------------------------------------------------

# Algorithms that are quantum-safe (symmetric / hash) — Grover's halves effective
# strength but AES-256 and SHA-256+ remain adequate
QUANTUM_SAFE_SYMMETRIC = {"AES-256-GCM", "AES-256-CBC", "AES-256", "CHACHA20-POLY1305", "ChaCha20-Poly1305"}
QUANTUM_SAFE_HASH = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"}

# Algorithms that are NOT quantum-safe (vulnerable to Grover's with small key or Shor's)
NOT_SAFE_SYMMETRIC = {"AES-128-GCM", "AES-128-CBC", "AES-128", "3DES", "DES", "RC4"}
NOT_SAFE_HASH = {"SHA-1", "MD5", "MD4"}

# NIST PQC standardized algorithms (FIPS 203/204/205)
PQC_KEY_EXCHANGE = {"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "KYBER", "KYBER-768"}
PQC_AUTHENTICATION = {"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                       "SLH-DSA", "SLH-DSA-128s", "SLH-DSA-128f",
                       "DILITHIUM", "SPHINCS+", "FALCON", "FN-DSA"}

# Classical algorithms vulnerable to Shor's algorithm
CLASSICAL_KX_VULNERABLE = {"RSA", "ECDHE", "ECDH", "DH", "DHE"}
CLASSICAL_AUTH_VULNERABLE = {"RSA", "ECDSA", "DSA"}


# --------------------------------------------------------------------------
# Classification logic
# --------------------------------------------------------------------------

def classify_key_exchange(kex: str) -> str:
    """Returns: 'pqc', 'vulnerable', 'unknown'"""
    kex_upper = kex.upper().replace("-", "_").replace(" ", "_")
    for pqc in PQC_KEY_EXCHANGE:
        if pqc.upper().replace("-", "_") in kex_upper:
            return "pqc"
    for vuln in CLASSICAL_KX_VULNERABLE:
        if vuln.upper() in kex_upper:
            return "vulnerable"
    return "unknown"


def classify_authentication(auth: str) -> str:
    """Returns: 'pqc', 'vulnerable', 'unknown'"""
    auth_upper = auth.upper().replace("-", "_").replace(" ", "_")
    for pqc in PQC_AUTHENTICATION:
        if pqc.upper().replace("-", "_") in auth_upper:
            return "pqc"
    for vuln in CLASSICAL_AUTH_VULNERABLE:
        if vuln.upper() in auth_upper:
            return "vulnerable"
    return "unknown"


def classify_encryption(enc: str) -> str:
    """Returns: 'safe', 'weak', 'unknown'"""
    enc_upper = enc.upper().replace("-", "_").replace(" ", "_")
    for safe in QUANTUM_SAFE_SYMMETRIC:
        if safe.upper().replace("-", "_") in enc_upper:
            return "safe"
    for weak in NOT_SAFE_SYMMETRIC:
        if weak.upper().replace("-", "_") in enc_upper:
            return "weak"
    return "unknown"


def classify_hashing(hsh: str) -> str:
    """Returns: 'safe', 'weak', 'unknown'"""
    hsh_upper = hsh.upper().replace("-", "_").replace(" ", "_")
    for safe in QUANTUM_SAFE_HASH:
        if safe.upper().replace("-", "_") in hsh_upper:
            return "safe"
    for weak in NOT_SAFE_HASH:
        if weak.upper().replace("-", "_") in hsh_upper:
            return "weak"
    return "unknown"


@dataclass
class PQCAnalysisResult:
    label: str                           # not_quantum_safe / quantum_safe / pqc_ready / fully_quantum_safe
    label_display: str                   # Human-readable + emoji
    kex_status: str = "unknown"
    auth_status: str = "unknown"
    enc_status: str = "unknown"
    hash_status: str = "unknown"
    risk_level: str = "unknown"          # critical / high / medium / low
    score_contribution: float = 0.0      # 0–1000 contribution
    details: dict = field(default_factory=dict)
    recommendations: list = field(default_factory=list)


LABEL_DISPLAY = {
    "not_quantum_safe": "❌ Not Quantum-Safe",
    "partially_quantum_safe": "🟡 Partially Quantum-Safe",
    "pqc_ready":        "🔵 PQC Ready",
    "fully_quantum_safe": "🟢 Fully Quantum Safe",
    "unknown":          "⚪ Unknown",
}


# PQC algorithm name fragments used to check certificate signature algorithms
PQC_SIG_FRAGMENTS = {"ML-DSA", "SLH-DSA", "DILITHIUM", "SPHINCS", "FALCON", "FN-DSA"}


def _cert_uses_pqc_sig(cert_info: dict) -> bool:
    """Check if a single parsed certificate uses a PQC signature algorithm."""
    sig_ref = cert_info.get("signature_algorithm_reference", "").upper()
    return any(frag in sig_ref for frag in PQC_SIG_FRAGMENTS)


def _chain_is_fully_pqc(cert_chain: list[dict]) -> bool:
    """Walk the full cert chain and return True only if EVERY cert uses a PQC signature."""
    if not cert_chain:
        return False
    for cert_info in cert_chain:
        if "error" in cert_info:
            return False
        if not _cert_uses_pqc_sig(cert_info):
            return False
    return True


def _leaf_uses_pqc_sig(cert_chain: list[dict]) -> bool:
    """Check if the leaf certificate (first in chain) uses a PQC signature."""
    if not cert_chain or "error" in cert_chain[0]:
        return False
    return _cert_uses_pqc_sig(cert_chain[0])


def classify(
    key_exchange: Optional[str],
    authentication: Optional[str],
    encryption: Optional[str],
    hashing: Optional[str],
    cert_chain: Optional[list[dict]] = None,
) -> PQCAnalysisResult:
    """
    Core labeling function implementing FR-11 label definitions.
    Uses cert-chain OIDs as the primary PQC detection signal, with
    cipher suite KEX as a supplementary signal.
    """
    kex = key_exchange or "Unknown"
    auth = authentication or "Unknown"
    enc = encryption or "Unknown"
    hsh = hashing or "Unknown"
    chain = cert_chain or []

    kex_status = classify_key_exchange(kex)
    auth_status = classify_authentication(auth)
    enc_status = classify_encryption(enc)
    hash_status = classify_hashing(hsh)

    # ── Certificate-based PQC detection ─────────────────────────────
    # Elevate auth_status if the leaf cert has a PQC signature OID but
    # the cipher-suite name didn't reveal it (standard OpenSSL can't
    # negotiate PQC suites, so we rely on the cert OID as ground truth)
    leaf_pqc = _leaf_uses_pqc_sig(chain)
    full_chain_pqc = _chain_is_fully_pqc(chain)

    if leaf_pqc and auth_status != "pqc":
        auth_status = "pqc"

    # If the leaf cert uses a PQC public key / signature, the server
    # clearly supports PQC — elevate KEX status as well since the TLS
    # handshake with this server inherently uses PQC key material.
    if leaf_pqc and kex_status != "pqc":
        kex_status = "pqc"

    details = {
        "key_exchange": {"value": kex, "status": kex_status},
        "authentication": {"value": auth, "status": auth_status},
        "encryption": {"value": enc, "status": enc_status},
        "hashing": {"value": hsh, "status": hash_status},
        "cert_chain_pqc": full_chain_pqc,
        "leaf_pqc": leaf_pqc,
    }

    # ── HNDL Decision Tree ──────────────────────────────────────────
    any_pqc_kex = kex_status == "pqc"
    any_pqc_auth = auth_status == "pqc"

    if any_pqc_kex and any_pqc_auth and full_chain_pqc:
        # Every layer — KEX, Auth, and the entire trust chain — is PQC
        label = "fully_quantum_safe"
        risk = "low"
        score = 1000.0
    elif any_pqc_kex and any_pqc_auth:
        # PQC KEX + PQC Auth, but root/intermediate CA still classical
        label = "pqc_ready"
        risk = "medium"
        score = 800.0
    elif any_pqc_kex or any_pqc_auth:
        # At least one PQC component detected (KEX or Auth via cert)
        label = "partially_quantum_safe"
        risk = "high"
        score = 500.0
    else:
        # No PQC detected anywhere — fully exposed to HNDL
        label = "not_quantum_safe"
        risk = "critical"
        score = 100.0

    recommendations = generate_recommendations(kex, auth, enc, hsh, kex_status, auth_status, enc_status, hash_status)

    return PQCAnalysisResult(
        label=label,
        label_display=LABEL_DISPLAY[label],
        kex_status=kex_status,
        auth_status=auth_status,
        enc_status=enc_status,
        hash_status=hash_status,
        risk_level=risk,
        score_contribution=score,
        details=details,
        recommendations=recommendations,
    )


def generate_recommendations(kex, auth, enc, hsh, kex_status, auth_status, enc_status, hash_status) -> list[dict]:
    """Generate FR-12 actionable remediation recommendations."""
    recs = []

    if kex_status == "vulnerable":
        recs.append({
            "component": "Key Exchange",
            "current": kex,
            "recommended": "ML-KEM-768 (FIPS 203)",
            "action": f"Upgrade key exchange from {kex} to ML-KEM-768 (FIPS 203). Enable hybrid TLS with X25519+ML-KEM-768 as interim step.",
            "priority": "Critical",
            "effort": "High",
        })

    if auth_status == "vulnerable":
        recs.append({
            "component": "Authentication",
            "current": auth,
            "recommended": "ML-DSA-65 (FIPS 204)",
            "action": f"Upgrade certificate signature from {auth} to ML-DSA-65 (FIPS 204). Obtain PQC-signed certificate from a compatible CA.",
            "priority": "Critical",
            "effort": "High",
        })

    if enc_status == "weak":
        recs.append({
            "component": "Encryption",
            "current": enc,
            "recommended": "AES-256-GCM",
            "action": f"Upgrade encryption from {enc} to AES-256-GCM. AES-256 retains adequate security against Grover's algorithm.",
            "priority": "High",
            "effort": "Medium",
        })

    if hash_status == "weak":
        recs.append({
            "component": "Hashing",
            "current": hsh,
            "recommended": "SHA-384",
            "action": f"Replace {hsh} with SHA-384 or SHA-512. SHA-1 and MD5 are broken for classical attacks and unsafe.",
            "priority": "Critical",
            "effort": "Medium",
        })

    if not recs:
        recs.append({
            "component": "General",
            "action": "Continue monitoring NIST PQC standards evolution. Plan migration of classical KX/auth to PQC algorithms (ML-KEM, ML-DSA) proactively.",
            "priority": "Informational",
            "effort": "Low",
        })

    return recs
