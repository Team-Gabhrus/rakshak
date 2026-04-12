"""
Debug Script 1: Raw TLS handshake analysis
Shows exactly what KEX and PKI your scanner sees vs what Chrome sees.

Usage:
    python scripts/debug_tls_kex.py support.google.com
"""
import ssl
import socket
import sys
import json
from urllib.parse import urlparse


def get_raw_tls_info(hostname: str, port: int = 443):
    """Connect using Python's built-in ssl module and dump everything."""
    print(f"\n{'='*70}")
    print(f"  RAW TLS HANDSHAKE: {hostname}:{port}")
    print(f"{'='*70}")

    ctx = ssl.create_default_context()
    # Don't restrict — let it negotiate the best it can
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Connection details
            print(f"\n[1] CONNECTION DETAILS")
            print(f"    TLS Version:      {ssock.version()}")
            print(f"    Cipher:           {ssock.cipher()}")

            cipher_name, tls_ver, bits = ssock.cipher()
            print(f"    Cipher Name:      {cipher_name}")
            print(f"    Cipher Bits:      {bits}")

            # Shared ciphers
            shared = ssock.shared_ciphers()
            if shared:
                print(f"\n[2] SHARED CIPHERS ({len(shared)} total)")
                for i, (name, ver, b) in enumerate(shared):
                    print(f"    [{i:2d}] {name:45s}  {ver}  {b} bits")

            # Certificate chain
            cert = ssock.getpeercert()
            print(f"\n[3] PEER CERTIFICATE")
            print(f"    Subject:          {dict(x[0] for x in cert['subject'])}")
            print(f"    Issuer:           {dict(x[0] for x in cert['issuer'])}")
            print(f"    Serial:           {cert.get('serialNumber', 'N/A')}")
            print(f"    Not Before:       {cert.get('notBefore', 'N/A')}")
            print(f"    Not After:        {cert.get('notAfter', 'N/A')}")

            # DER cert for deeper analysis
            der_cert = ssock.getpeercert(binary_form=True)
            print(f"    DER cert size:    {len(der_cert)} bytes")

            return {
                "tls_version": ssock.version(),
                "cipher": ssock.cipher(),
                "cert_subject": dict(x[0] for x in cert['subject']),
                "cert_issuer": dict(x[0] for x in cert['issuer']),
                "der_cert": der_cert,
            }


def analyze_cert_with_cryptography(der_cert: bytes):
    """Use the cryptography library to inspect the certificate's signature algo."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    except ImportError:
        print("\n  [!] 'cryptography' library not installed. Skipping cert analysis.")
        return

    cert = x509.load_der_x509_certificate(der_cert)

    print(f"\n[4] CERTIFICATE DEEP ANALYSIS (via cryptography library)")
    print(f"    Signature Algorithm OID:    {cert.signature_algorithm_oid.dotted_string}")
    try:
        sig_hash = cert.signature_hash_algorithm
        print(f"    Signature Hash Algorithm:   {sig_hash.name if sig_hash else 'None'}")
    except Exception as e:
        print(f"    Signature Hash Algorithm:   Error: {e}")

    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        print(f"    Public Key Type:            RSA ({pub_key.key_size} bits)")
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        print(f"    Public Key Type:            ECDSA ({pub_key.curve.name}, {pub_key.key_size} bits)")
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        print(f"    Public Key Type:            Ed25519 (256 bits)")
    else:
        print(f"    Public Key Type:            {type(pub_key).__name__}")

    # Check PQC OIDs
    from app.engine.cert_parser import PQC_OIDS
    oid = cert.signature_algorithm_oid.dotted_string
    if oid in PQC_OIDS:
        print(f"    *** PQC SIGNATURE DETECTED: {PQC_OIDS[oid]} ***")
    else:
        print(f"    PQC Signature:              NOT DETECTED (OID {oid} not in PQC_OIDS)")


def analyze_python_ssl_capabilities():
    """Check what Python's ssl module can actually negotiate."""
    print(f"\n{'='*70}")
    print(f"  PYTHON SSL LIBRARY CAPABILITIES")
    print(f"{'='*70}")
    print(f"    OpenSSL version:  {ssl.OPENSSL_VERSION}")
    print(f"    OpenSSL number:   {ssl.OPENSSL_VERSION_NUMBER:#x}")

    # Check if this OpenSSL supports ML-KEM / X25519_MLKEM768
    has_pqc = False
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ciphers = ctx.get_ciphers()
    for c in ciphers:
        name = c.get("name", "").upper()
        if "MLKEM" in name or "ML_KEM" in name or "KYBER" in name:
            has_pqc = True
            print(f"    PQC cipher found: {c['name']}")

    if not has_pqc:
        print(f"\n    *** CRITICAL: Python's OpenSSL ({ssl.OPENSSL_VERSION}) does NOT")
        print(f"        support ML-KEM / X25519_MLKEM768 key exchange! ***")
        print(f"        This means sslyze (which uses Python's ssl) will NEVER see PQC KEX.")

    # Check supported groups if available
    print(f"\n    TLS 1.3 support:  {hasattr(ssl, 'TLSVersion') and hasattr(ssl.TLSVersion, 'TLSv1_3')}")


def simulate_rakshak_scan(hostname: str):
    """Run the actual Rakshak scan pipeline and show what it detects."""
    print(f"\n{'='*70}")
    print(f"  RAKSHAK SCANNER SIMULATION: {hostname}")
    print(f"{'='*70}")

    import asyncio
    from app.engine.tls_scanner import scan_target, parse_cipher_name
    from app.engine.pqc_classifier import classify, classify_key_exchange, classify_authentication

    result = asyncio.run(scan_target(hostname))

    print(f"\n[5] TLS SCANNER OUTPUT")
    print(f"    Success:          {result.success}")
    print(f"    Error:            {result.error}")
    print(f"    TLS Version:      {result.tls_version}")
    print(f"    Negotiated Cipher:{result.negotiated_cipher}")
    print(f"    Key Exchange:     {result.key_exchange}")
    print(f"    Authentication:   {result.authentication}")
    print(f"    Encryption:       {result.encryption}")
    print(f"    Hashing:          {result.hashing}")

    print(f"\n[6] KEX CLASSIFICATION")
    kex_class = classify_key_exchange(result.key_exchange or "Unknown")
    auth_class = classify_authentication(result.authentication or "Unknown")
    print(f"    classify_key_exchange('{result.key_exchange}') = '{kex_class}'")
    print(f"    classify_authentication('{result.authentication}') = '{auth_class}'")

    print(f"\n[7] CERT CHAIN")
    for i, cert in enumerate(result.cert_chain):
        if "error" in cert:
            print(f"    [{i}] ERROR: {cert['error']}")
        else:
            print(f"    [{i}] {cert.get('name', '?'):40s}  sig={cert.get('signature_algorithm_reference', '?')}")
            print(f"         key={cert.get('key_algorithm', '?')} ({cert.get('key_length', '?')} bits)")

    print(f"\n[8] PQC CLASSIFIER OUTPUT")
    pqc_result = classify(
        key_exchange=result.key_exchange,
        authentication=result.authentication,
        encryption=result.encryption,
        hashing=result.hashing,
        cert_chain=result.cert_chain,
        supported_versions=result.supported_tls_versions,
        cipher_suites=result.cipher_suites,
    )

    print(f"    Label:            {pqc_result.label}")
    print(f"    Label Display:    {pqc_result.label_display}")
    print(f"    KEX Status:       {pqc_result.kex_status}")
    print(f"    Auth Status:      {pqc_result.auth_status}")
    print(f"    Enc Status:       {pqc_result.enc_status}")
    print(f"    Hash Status:      {pqc_result.hash_status}")
    print(f"    Risk Level:       {pqc_result.risk_level}")
    print(f"    Score:            {pqc_result.score_contribution}")
    print(f"    Details:          {json.dumps(pqc_result.details, indent=6)}")

    if pqc_result.recommendations:
        print(f"\n[9] RECOMMENDATIONS")
        for rec in pqc_result.recommendations:
            print(f"    - [{rec.get('priority', '?')}] {rec.get('component', '?')}: {rec.get('action', '?')[:100]}")

    return result, pqc_result


def explain_the_gap():
    """Print a clear explanation of the Chrome-vs-Rakshak gap."""
    print(f"\n{'='*70}")
    print(f"  ROOT CAUSE ANALYSIS")
    print(f"{'='*70}")
    print("""
    WHAT CHROME SEES:
    ─────────────────
    KEX:  X25519_MLKEM768  ← This is a HYBRID key exchange. Chrome's BoringSSL
          supports ML-KEM-768 (FIPS 203) and negotiates it in a hybrid mode
          with X25519, providing both classical AND post-quantum KEX security.

    PKI:  ecdsa_secp256r1_sha256  ← The server's certificate is signed with
          ECDSA (P-256), which is a CLASSICAL algorithm vulnerable to Shor's
          algorithm on a quantum computer.

    WHAT YOUR SCANNER (RAKSHAK) SEES:
    ──────────────────────────────────
    KEX:  ECDHE (via sslyze)  ← sslyze uses Python's OpenSSL, which typically
          does NOT support ML-KEM. So sslyze can only negotiate classical ECDHE.
          It NEVER sees X25519_MLKEM768 because it can't offer it.

    PKI:  ECDSA  ← Same as Chrome. This is correct.

    THE CORE PROBLEM:
    ─────────────────
    1. sslyze (your primary scanner) uses Python's bundled OpenSSL, which
       does NOT support X25519_MLKEM768 hybrid key exchange. So the KEX
       always shows as classical ECDHE, regardless of server capability.

    2. Your OQS Docker probe COULD detect PQC, but it looks for pure ML-KEM
       groups (-groups mlkem768). Google's servers use HYBRID X25519_MLKEM768,
       not pure mlkem768. The OQS probe likely fails to negotiate because it
       only offers pure PQC groups.

    3. Even if KEX were detected correctly, the CLASSIFIER correctly requires
       BOTH PQC KEX AND PQC authentication for "pqc_ready" or higher. Since
       support.google.com uses ECDSA (classical) certificates, it would at
       BEST be "partially_quantum_safe" — PQC KEX but classical auth.

    4. Chrome shows "Secure" because hybrid PQC KEX protects against
       harvest-now-decrypt-later (HNDL) attacks on the KEY EXCHANGE.
       But the CERTIFICATE is still classically signed (ECDSA).

    VERDICT:
    ────────
    Your scanner is TECHNICALLY CORRECT to flag it as "not quantum safe"
    from a HOLISTIC perspective because:
    - The certificate chain uses ECDSA (vulnerable to Shor's)
    - sslyze can't detect the hybrid PQC KEX at all

    However, it's MISSING the partial PQC protection (hybrid KEX) that
    Chrome negotiates. To fix this, you need to:
    1. Detect X25519_MLKEM768 hybrid KEX (not just pure ML-KEM)
    2. Report it as "partially_quantum_safe" — PQC KEX, classical auth
    """)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "support.google.com"

    # Strip URL to hostname
    if "://" in target:
        target = urlparse(target).hostname or target

    analyze_python_ssl_capabilities()
    info = get_raw_tls_info(target)
    analyze_cert_with_cryptography(info["der_cert"])

    try:
        simulate_rakshak_scan(target)
    except Exception as e:
        print(f"\n[!] Rakshak scan failed: {e}")
        import traceback
        traceback.print_exc()

    explain_the_gap()
