"""
Certificate parser using the Python cryptography library.
Covers FR-04: issuer, subject, sig algorithm, public key algo, key length, validity, chain.
"""
from datetime import datetime
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

PQC_OIDS = {
    # ML-DSA / Dilithium OIDs
    "1.3.6.1.4.1.2.267.12.4.4": "ML-DSA-44",
    "1.3.6.1.4.1.2.267.12.4.6": "ML-DSA-65",
    "1.3.6.1.4.1.2.267.12.4.8": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    # SLH-DSA / SPHINCS+ OIDs
    "1.3.9999.6.4.13": "SLH-DSA-128s", 
    "1.3.9999.6.4.16": "SLH-DSA-128s",
    # MLDSA + RSA / ECDSA Hybrids
    "1.3.9999.2.7.1": "RSA3072-ML-DSA-44",
    # Falcon / FN-DSA
    "1.3.9999.3.6": "Falcon-512",
    "1.3.9999.3.9": "Falcon-1024",
    "2.16.840.1.101.3.4.3.20": "FN-DSA-512",
    "2.16.840.1.101.3.4.3.21": "FN-DSA-1024",
}

def get_key_info(public_key) -> tuple[str, int]:
    """Extract algorithm name and key length from a public key."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECDSA ({public_key.curve.name})", public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    else:
        return "Unknown", 0


def get_oid_for_algorithm(sig_algo_name: str) -> str:
    """Return common OIDs for known algorithms."""
    oid_map = {
        "sha256WithRSAEncryption": "1.2.840.113549.1.1.11",
        "sha384WithRSAEncryption": "1.2.840.113549.1.1.12",
        "sha512WithRSAEncryption": "1.2.840.113549.1.1.13",
        "sha1WithRSAEncryption": "1.2.840.113549.1.1.5",
        "ecdsa-with-SHA256": "1.2.840.10045.4.3.2",
        "ecdsa-with-SHA384": "1.2.840.10045.4.3.3",
        "ecdsa-with-SHA512": "1.2.840.10045.4.3.4",
    }
    return oid_map.get(sig_algo_name, "unknown")


def parse_single_cert(cert: x509.Certificate) -> dict:
    """Parse a single X.509 certificate into CBOM-ready fields (FR-04, Annexure-A Certificates)."""
    try:
        pub_key = cert.public_key()
        key_algo, key_length = get_key_info(pub_key)
    except Exception:
        key_algo = "PQC / Unrecognized"
        key_length = 0

    try:
        sig_algo = cert.signature_algorithm_oid.dotted_string
        if sig_algo in PQC_OIDS:
            sig_algo_name = PQC_OIDS[sig_algo]
        else:
            sig_algo_name = getattr(cert.signature_hash_algorithm, "name", "unknown") if hasattr(cert, 'signature_hash_algorithm') and cert.signature_hash_algorithm else "unknown"
    except Exception:
        sig_algo = "unknown"
        sig_algo_name = "unknown"

    try:
        subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        subject_name = subject_cn[0].value if subject_cn else str(cert.subject)
    except Exception:
        subject_name = str(cert.subject)

    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer_name = issuer_cn[0].value if issuer_cn else str(cert.issuer)
    except Exception:
        issuer_name = str(cert.issuer)

    # Certificate extensions
    extensions = []
    try:
        for ext in cert.extensions:
            extensions.append(ext.oid.dotted_string)
    except Exception:
        pass

    return {
        # CERT-IN Annexure-A — Certificates category fields
        "name": subject_name,
        "asset_type": "certificate",
        "subject_name": str(cert.subject),
        "issuer_name": issuer_name,
        "not_valid_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat(),
        "signature_algorithm_reference": f"{sig_algo_name} ({sig_algo})",
        "subject_public_key_reference": f"{key_algo} ({key_length} bits)",
        "certificate_format": "X.509",
        "certificate_extension": ".crt",
        # Extra useful fields
        "key_algorithm": key_algo,
        "key_length": key_length,
        "serial_number": str(cert.serial_number),
        "extensions": extensions,
        "is_ca": _is_ca(cert),
    }


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bc.value.ca
    except Exception:
        return False


def parse_certificate_chain(chain) -> list[dict]:
    """Parse a full certificate chain (list of x509.Certificate objects)."""
    parsed = []
    for cert in chain:
        try:
            parsed.append(parse_single_cert(cert))
        except Exception as e:
            parsed.append({"error": str(e)})
    return parsed


def parse_cert_from_pem(pem_data: bytes) -> Optional[dict]:
    try:
        cert = x509.load_pem_x509_certificate(pem_data)
        return parse_single_cert(cert)
    except Exception:
        return None
