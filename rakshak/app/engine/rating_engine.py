"""
Cyber Rating Engine — FR-47, FR-48, FR-49, FR-50.
Computes enterprise-level score (0–1000), tier classification, and tracks history.
"""
from typing import Optional


# Scoring weights per PQC label (FR-48 classification table)
LABEL_SCORE = {
    "fully_quantum_safe": 1000,
    "pqc_ready": 700,
    "partially_quantum_safe": 400,
    "not_quantum_safe": 100,
    "unknown": 200,
    "intranet_only": 150,  # Exists but unreachable from internet — assume classical until proven otherwise
    "dns_failed": 0,       # Hostname doesn't exist publicly
}

# FR-49: Compliance Matrix — Tier definitions
COMPLIANCE_MATRIX = [
    {
        "tier": 1,
        "name": "Elite",
        "label": "Tier 1 — Elite",
        "score_min": 800,
        "score_max": 1000,
        "security_level": "Fully Quantum Safe",
        "compliance_criteria": "TLS 1.3 with ML-KEM key exchange + ML-DSA authentication + AES-256-GCM + SHA-384",
        "priority_action": "Maintain posture; monitor NIST PQC evolution; implement SLH-DSA backup.",
        "badge_color": "#2ECC71",
    },
    {
        "tier": 2,
        "name": "Standard",
        "label": "Tier 2 — Standard",
        "score_min": 600,
        "score_max": 799,
        "security_level": "PQC Ready",
        "compliance_criteria": "TLS 1.2/1.3 with at least one PQC algorithm (ML-KEM or ML-DSA) in use.",
        "priority_action": "Complete PQC migration. Prioritize remaining classical KX/auth components.",
        "badge_color": "#3498DB",
    },
    {
        "tier": 3,
        "name": "Needs Improvement",
        "label": "Tier 3 — Needs Improvement",
        "score_min": 300,
        "score_max": 599,
        "security_level": "Quantum-Safe (Classical KX/Auth)",
        "compliance_criteria": "TLS 1.2+ with AES-256 + SHA-256/384, but RSA/ECDSA still used for KX/auth.",
        "priority_action": "Initiate PQC migration project. Prioritize HNDL-exposed assets immediately.",
        "badge_color": "#F1C40F",
    },
    {
        "tier": 4,
        "name": "Critical",
        "label": "Tier 4 — Critical",
        "score_min": 0,
        "score_max": 299,
        "security_level": "Not Quantum-Safe",
        "compliance_criteria": "Legacy algorithms in use: RSA-1024, SHA-1, RC4, TLS 1.0/1.1, or DES.",
        "priority_action": "URGENT: Immediate remediation required. Disable legacy protocols. Apply PQC migration plan.",
        "badge_color": "#E74C3C",
    },
]

# FR-48: Classification table mapping asset status to score ranges
CLASSIFICATION_TABLE = [
    {"status": "Elite-PQC Ready", "score_min": 900, "score_max": 1000, "description": "All components fully quantum-safe per NIST PQC standards"},
    {"status": "Standard",        "score_min": 600, "score_max": 899,  "description": "Partial PQC migration completed"},
    {"status": "Legacy",          "score_min": 300, "score_max": 599,  "description": "Classical algorithms only, symmetric/hash are quantum-safe"},
    {"status": "Critical",        "score_min": 0,   "score_max": 299,  "description": "Vulnerable legacy algorithms in active use"},
]


def compute_enterprise_score(label_counts: dict) -> dict:
    """
    Compute enterprise-level cyber rating score (FR-47).
    label_counts: {"fully_quantum_safe": N, "pqc_ready": N, "quantum_safe": N, "not_quantum_safe": N, "unknown": N}
    Returns: {score, tier, classification, breakdown}
    """
    total = sum(label_counts.values())
    if total == 0:
        return {"score": 0, "tier": 4, "tier_label": "Critical", "total_assets": 0, "breakdown": label_counts}

    weighted_sum = sum(LABEL_SCORE.get(label, 200) * count for label, count in label_counts.items())
    score = round(weighted_sum / total)

    # Determine tier
    tier_info = COMPLIANCE_MATRIX[-1]  # default Critical
    for t in COMPLIANCE_MATRIX:
        if t["score_min"] <= score <= t["score_max"]:
            tier_info = t
            break

    return {
        "score": score,
        "tier": tier_info["tier"],
        "tier_name": tier_info["name"],
        "tier_label": tier_info["label"],
        "security_level": tier_info["security_level"],
        "badge_color": tier_info["badge_color"],
        "total_assets": total,
        "breakdown": label_counts,
        "compliance_matrix": COMPLIANCE_MATRIX,
        "classification_table": CLASSIFICATION_TABLE,
    }


def get_risk_level_from_label(label: str) -> str:
    mapping = {
        "fully_quantum_safe": "low",
        "pqc_ready": "medium",
        "partially_quantum_safe": "high",
        "not_quantum_safe": "critical",
        "unknown": "unknown",
        "intranet_only": "unknown",  # Cannot assess without network access
        "dns_failed": "unknown",     # Host doesn't exist
    }
    return mapping.get(label, "unknown")
