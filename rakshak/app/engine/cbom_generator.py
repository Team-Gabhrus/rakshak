"""
CBOM Generator — FR-10, FR-13
Generates Cryptographic Bill of Materials per CERT-IN Annexure-A.
Four categories: Algorithms, Keys, Protocols, Certificates.
"""
import hashlib
import json
from datetime import datetime
from typing import Optional



def build_key_entry(cipher_info: dict, cert_info: Optional[dict] = None) -> dict:
    """Build Annexure-A Key entry."""
    key_name = cert_info.get("subject_name", "TLS Session Key") if cert_info else "TLS Session Key"
    key_size = cert_info.get("key_length", cipher_info.get("bits", 256)) if cert_info else cipher_info.get("bits", 256)

    not_before = cert_info.get("not_valid_before") if cert_info else None
    not_after = cert_info.get("not_valid_after") if cert_info else None

    now = datetime.utcnow().isoformat()
    state = "active"
    if not_after:
        try:
            exp = datetime.fromisoformat(not_after.replace("Z", ""))
            state = "expired" if exp < datetime.utcnow() else "active"
        except Exception:
            pass

    return {
        "name": key_name,
        "asset_type": "key",
        "id": f"key-{hashlib.md5(key_name.encode()).hexdigest()[:8]}",
        "state": state,
        "size": f"{key_size} bits",
        "creation_date": not_before or now,
        "activation_date": not_before or now,
        "expiry_date": not_after,
    }


def build_protocol_entry(tls_version: str, cipher_suites: list) -> dict:
    """Build Annexure-A Protocol entry."""
    oid_map = {
        "TLS 1.3": "1.3.18.0.2.32.104",
        "TLS 1.2": "1.3.18.0.2.32.103",
        "TLS 1.1": "1.3.18.0.2.32.102",
        "TLS 1.0": "1.3.18.0.2.32.101",
        "SSL 3.0": "1.3.18.0.2.32.100",
    }
    return {
        "name": "TLS",
        "asset_type": "protocol",
        "version": tls_version or "Unknown",
        "cipher_suites": [cs.get("name", "") for cs in cipher_suites[:10]],  # top 10
        "oid": oid_map.get(tls_version, "unknown"),
    }


def generate_cbom(
    target_url: str,
    tls_version: Optional[str],
    cipher_suites: list,
    cert_chain: list,
    pqc_label: str,
    negotiated_cipher_info: Optional[dict] = None,
) -> dict:
    """
    Generate a complete CBOM per CERT-IN Annexure-A (FR-10).
    Returns a dict with four Annexure-A categories.
    """
    algorithms = []
    keys = []
    protocols = []
    certificates = []

    # Algorithms — from negotiated cipher and all cipher suites
    seen_algs = set()
    
    # Internal helper to add alg
    def add_alg(name, primitive, funcs):
        if not name or name == "Unknown" or name in seen_algs:
            return
        
        # Determine classical security approximation
        sec_level = "256 bits"
        if "384" in name: sec_level = "384 bits"
        elif "128" in name or "160" in name: sec_level = "128 bits"
        
        oid_map = {
            "AES-256-GCM": "2.16.840.1.101.3.4.1.46",
            "AES-256-CBC": "2.16.840.1.101.3.4.1.42",
            "AES-128-GCM": "2.16.840.1.101.3.4.1.6",
            "AES-128-CBC": "2.16.840.1.101.3.4.1.2",
            "SHA-256": "2.16.840.1.101.3.4.2.1",
            "SHA-384": "2.16.840.1.101.3.4.2.2",
            "SHA-512": "2.16.840.1.101.3.4.2.3",
            "ChaCha20-Poly1305": "1.2.840.113549.1.9.16.3.18",
            "CAMELLIA-256-CBC": "1.2.392.200011.61.1.1.1.4",
            "CAMELLIA-128-CBC": "1.2.392.200011.61.1.1.1.2",
            "ARIA-256-GCM": "1.2.410.200046.1.1.37",
            "ARIA-128-GCM": "1.2.410.200046.1.1.34",
            "ARIA-256-CBC": "1.2.410.200046.1.1.13",
            "ARIA-128-CBC": "1.2.410.200046.1.1.8",

            "CAMELLIA-256-CBC": "1.2.392.200011.61.1.1.1.4",
            "CAMELLIA-128-CBC": "1.2.392.200011.61.1.1.1.2",
            "ARIA-256-GCM": "1.2.410.200046.1.1.37",
            "ARIA-128-GCM": "1.2.410.200046.1.1.34",
            "ARIA-256-CBC": "1.2.410.200046.1.1.13",
            "ARIA-128-CBC": "1.2.410.200046.1.1.8",

            "ML-KEM": "2.16.840.1.101.3.4.4.1",  # Approximate OID mapping
            "ML-DSA": "2.16.840.1.101.3.4.3.17", # Approximate OID mapping
            "RSA": "1.2.840.113549.1.1.1",
            "ECDSA": "1.2.840.10045.2.1",
            "ECDHE": "1.3.132.1.12"
        }
        
        algorithms.append({
            "name": name,
            "asset_type": "algorithm",
            "primitive": primitive,
            "mode": "GCM" if "GCM" in name else ("CBC" if "CBC" in name else "N/A"),
            "crypto_functions": funcs,
            "classical_security_level": sec_level,
            "oid": oid_map.get(name, "unknown"),
            "list": [name],
        })
        seen_algs.add(name)

    for cs in cipher_suites:
        # 1. Encryption
        enc = cs.get("encryption", "Unknown")
        funcs_enc = []
        if "AES" in enc or "ChaCha" in enc or "CAMELLIA" in enc or "ARIA" in enc:
            funcs_enc = ["key generation", "encryption", "decryption", "authentication tag generation"]
        add_alg(enc, "symmetric-encryption", funcs_enc)

        # 2. Hashing
        hsh = cs.get("hashing", "Unknown")
        add_alg(hsh, "hash", ["hashing", "integrity verification"])
        
        # 3. Key Exchange
        kex = cs.get("key_exchange", "Unknown")
        add_alg(kex, "key-exchange", ["key generation", "key encapsulation", "agreement"])
        
        # 4. Authentication
        auth = cs.get("authentication", "Unknown")
        add_alg(auth, "signature", ["digital signature", "authentication"])

    # Protocols
    protocols.append(build_protocol_entry(tls_version, cipher_suites))

    # Keys + Certificates — from cert chain
    for cert in cert_chain:
        if "error" in cert:
            continue
        key_entry = build_key_entry(negotiated_cipher_info or {}, cert)
        keys.append(key_entry)
        certificates.append(cert)

    cbom = {
        "target": target_url,
        "pqc_label": pqc_label,
        "generated_at": datetime.utcnow().isoformat(),
        "algorithms": algorithms,
        "keys": keys,
        "protocols": protocols,
        "certificates": certificates,
    }
    return cbom


def compute_cbom_hash(cbom: dict) -> str:
    """Compute SHA-256 hash of CBOM for snapshot integrity."""
    serialized = json.dumps(cbom, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def diff_cbom_snapshots(snapshot_a: dict, snapshot_b: dict) -> dict:
    """
    Compare two CBOM snapshots (FR-13).
    Returns added, removed, and changed items per category.
    """
    result = {}
    categories = ["algorithms", "keys", "protocols", "certificates"]

    for cat in categories:
        a_items = {item.get("name", str(i)): item for i, item in enumerate(snapshot_a.get(cat, []))}
        b_items = {item.get("name", str(i)): item for i, item in enumerate(snapshot_b.get(cat, []))}

        added = [b_items[k] for k in b_items if k not in a_items]
        removed = [a_items[k] for k in a_items if k not in b_items]
        changed = []
        for k in a_items:
            if k in b_items and a_items[k] != b_items[k]:
                changed.append({"name": k, "before": a_items[k], "after": b_items[k]})

        result[cat] = {
            "added": added,
            "removed": removed,
            "changed": changed,
        }

    result["summary"] = {
        "snapshot_a_date": snapshot_a.get("generated_at"),
        "snapshot_b_date": snapshot_b.get("generated_at"),
        "pqc_label_changed": snapshot_a.get("pqc_label") != snapshot_b.get("pqc_label"),
        "pqc_label_before": snapshot_a.get("pqc_label"),
        "pqc_label_after": snapshot_b.get("pqc_label"),
    }

    return result
