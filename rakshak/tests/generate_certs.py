#!/usr/bin/env python3
"""
Rakshak Test Server Generator
Creates self-signed TLS certificates for local test servers.
Run this FIRST before starting test servers.
"""
import subprocess
import os
from pathlib import Path

CERTS_DIR = Path(__file__).parent / "certs"
CERTS_DIR.mkdir(exist_ok=True)

SERVERS = [
    {
        "name": "strong_tls13",
        "cn": "strong.rakshak.test",
        "desc": "TLS 1.3 Only — AES-256-GCM — ECDSA P-384",
    },
    {
        "name": "legacy_tls10",
        "cn": "legacy.rakshak.test",
        "desc": "TLS 1.0/1.1 — RC4 / AES-128 — RSA 1024",
    },
    {
        "name": "weak_rsa2048",
        "cn": "rsa2048.rakshak.test",
        "desc": "TLS 1.2 — AES-128-GCM — RSA 2048 (No PQC)",
    },
    {
        "name": "modern_ecdsa",
        "cn": "ecdsa.rakshak.test",
        "desc": "TLS 1.3 — AES-256-GCM — ECDSA P-256",
    },
]


def generate_cert(name: str, cn: str):
    """Generate a self-signed certificate using openssl."""
    key_file  = CERTS_DIR / f"{name}.key"
    cert_file = CERTS_DIR / f"{name}.crt"

    if key_file.exists() and cert_file.exists():
        print(f"  [SKIP] {name} — certs already exist")
        return str(key_file), str(cert_file)

    # Try openssl first
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_file),
            "-out", str(cert_file),
            "-days", "365",
            "-nodes",
            "-subj", f"/CN={cn}/O=Rakshak Test/C=IN",
        ], check=True, capture_output=True)
        print(f"  [OK] Generated cert for {cn}")
        return str(key_file), str(cert_file)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Fallback: use Python cryptography library
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Rakshak Test"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("localhost")]), critical=False)
            .sign(private_key, hashes.SHA256())
        )

        key_file.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        ))
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        print(f"  [OK] Generated cert for {cn} (via Python cryptography)")
        return str(key_file), str(cert_file)
    except ImportError:
        print(f"  [WARN] Could not generate cert for {cn} — install cryptography library")
        return None, None


if __name__ == "__main__":
    print("Generating TLS test certificates...\n")
    for srv in SERVERS:
        print(f"→ {srv['name']}: {srv['desc']}")
        key, cert = generate_cert(srv["name"], srv["cn"])
        if key:
            print(f"    Key:  {key}")
            print(f"    Cert: {cert}")
    print("\nDone! Now run: python test_servers.py")
