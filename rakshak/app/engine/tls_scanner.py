"""
TLS Scanner using sslyze — performs TLS handshakes and enumerates cipher suites.
Covers FR-02, FR-03, FR-04 (via cert_parser), FR-05 (VPN), FR-06 (API).
Falls back to OQS Docker probe for PQC-only servers.
"""
import asyncio
import json
import logging
import subprocess
import re
import shutil
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# ── OQS Docker Probe ────────────────────────────────────────────────
OQS_DOCKER_IMAGE = "openquantumsafe/curl:latest"

# Known PQC public-key sizes (bytes) for display
PQC_KEY_SIZES = {
    "ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592,
    "MLDSA44": 1312, "MLDSA65": 1952, "MLDSA87": 2592,
    "Falcon-512": 897, "Falcon-1024": 1793,
    "FALCON512": 897, "FALCON1024": 1793,
    "SLH-DSA-128s": 32, "SLH-DSA-128f": 32,
}

def _docker_available() -> bool:
    """Check if Docker CLI is available."""
    return shutil.which("docker") is not None

def _oqs_probe(host: str, port: int, timeout: int = 30) -> Optional[dict]:
    """
    Use the OQS Docker container to probe a PQC-enabled server.
    Runs full `openssl s_client` with -showcerts and PQC groups to get:
    - Complete cert chain with per-cert sigalg (mldsa44, RSA-SHA256, etc.)
    - PQC KEX detection via -groups mlkem768
    - Signature type / auth algorithm
    Returns dict with parsed fields or None on failure.
    """
    if not _docker_available():
        logger.warning("Docker not available — skipping OQS probe")
        return None

    try:
        cmd = [
            "docker", "run", "--rm", "-i",
            OQS_DOCKER_IMAGE,
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,  # Fix SNI
            "-showcerts",            # Show the full certificate chain
            # Try hybrid first (Chrome/BoringSSL style), then pure PQC as fallback.
            # Google & most real servers use hybrid X25519+ML-KEM-768, not pure ML-KEM.
            "-groups", "x25519_mlkem768:x25519_kyber768:mlkem768:x25519",
        ]
        logger.info(f"OQS probe cmd: {' '.join(cmd)}")
        proc = subprocess.run(
            cmd, input=b"Q\n", capture_output=True, timeout=timeout,
        )
        output = (proc.stdout.decode("utf-8", errors="replace") +
                  proc.stderr.decode("utf-8", errors="replace"))
        logger.info(f"OQS probe raw output for {host}:{port} ({len(output)} chars)")

        if "CONNECTED" not in output:
            logger.info(f"OQS probe to {host}:{port} did not connect")
            return None

        result = {}

        # Parse from the full s_client output
        for line in output.splitlines():
            stripped = line.strip()

            # "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
            if "Cipher is " in stripped:
                m = re.search(r"Cipher is (\S+)", stripped)
                if m:
                    result["ciphersuite"] = m.group(1)

            # "Protocol  : TLSv1.3"
            if "Protocol" in stripped and ":" in stripped and "TLS" in stripped:
                m = re.search(r"Protocol\s*:\s*(\S+)", stripped)
                if m:
                    result["tls_version"] = m.group(1)

            # "Server Temp Key: X25519, 253 bits" (TLS 1.2) or nothing in TLS 1.3
            if stripped.startswith("Server Temp Key:"):
                result["server_temp_key"] = stripped.split(":", 1)[1].strip()

            # "Peer signing digest: ..." or "Peer signature type: mldsa44"
            if stripped.startswith("Signature type:") or stripped.startswith("Peer signature type:"):
                result["signature_type"] = stripped.split(":", 1)[1].strip()

            # "Signature Algorithm: mldsa44" (from cert PEM blocks with -showcerts)
            if "Signature Algorithm:" in stripped:
                sig_algo = stripped.split(":", 1)[1].strip()
                result.setdefault("signature_algorithms", []).append(sig_algo)

            # "Public-Key: (1312 bit)"
            if "Public-Key:" in stripped:
                m = re.search(r"\((\d+) bit\)", stripped)
                if m:
                    result.setdefault("public_key_bits", []).append(int(m.group(1)))

            if "Public Key Algorithm:" in stripped:
                algo = stripped.split(":", 1)[1].strip()
                result.setdefault("public_key_algos", []).append(algo)

        # ── Parse the "Certificate chain" block ──────────────────────────────
        # This block (before "Server certificate") shows full chain info like:
        #  0 s:CN=localhost
        #    i:CN=My_Classical_Root_CA
        #    a:PKEY: UNDEF, 128 (bit); sigalg: mldsa44
        # We parse depth, CN, and per-cert sigalg from here.
        chain_entries = {}  # depth -> dict
        lines = output.splitlines()
        in_chain_block = False
        current_depth = None
        for line in lines:
            stripped = line.strip()
            if stripped == "Certificate chain":
                in_chain_block = True
                continue
            if in_chain_block and (stripped.startswith("---") or stripped.startswith("Server certificate")):
                in_chain_block = False
                continue
            if in_chain_block:
                # "0 s:CN=localhost" — depth + subject
                m_depth = re.match(r"(\d+)\s+s:(.+)", stripped)
                if m_depth:
                    current_depth = int(m_depth.group(1))
                    dn = m_depth.group(2).strip()
                    cn_match = re.search(r"CN\s*=\s*([^,/]+)", dn)
                    cn = cn_match.group(1).strip() if cn_match else dn
                    chain_entries.setdefault(current_depth, {"depth": current_depth, "cn": cn, "dn": dn})
                    continue
                # "  i:CN=My_Classical_Root_CA" — issuer at current_depth + 1
                m_issuer = re.match(r"i:(.+)", stripped)
                if m_issuer and current_depth is not None:
                    issuer_dn = m_issuer.group(1).strip()
                    issuer_cn_match = re.search(r"CN\s*=\s*([^,/]+)", issuer_dn)
                    issuer_cn = issuer_cn_match.group(1).strip() if issuer_cn_match else issuer_dn
                    # Create an entry for the issuer (depth+1) if it doesn't have one
                    next_depth = current_depth + 1
                    if next_depth not in chain_entries:
                        chain_entries[next_depth] = {"depth": next_depth, "cn": issuer_cn, "dn": issuer_dn}
                    continue
                # "  a:PKEY: UNDEF, 128 (bit); sigalg: mldsa44" — attributes of current cert
                m_attr = re.match(r"a:(.+)", stripped)
                if m_attr and current_depth is not None:
                    attr_str = m_attr.group(1)
                    sigalg_m = re.search(r"sigalg:\s*(\S+)", attr_str)
                    if sigalg_m and current_depth in chain_entries:
                        chain_entries[current_depth]["sigalg"] = sigalg_m.group(1)
                        # sigalg = the algorithm used by the ISSUER to sign this cert.
                        # Propagate it to the issuer entry (depth+1) so the root CA is labeled correctly.
                        issuer_depth = current_depth + 1
                        if issuer_depth in chain_entries:
                            chain_entries[issuer_depth].setdefault("sigalg", sigalg_m.group(1))

        # Deduplicate verify-error depth lines ("depth=0 CN=localhost")
        # and merge into chain_entries
        for line in lines:
            m = re.search(r"depth=(\d+)\s+(.+)", line.strip())
            if m:
                depth = int(m.group(1))
                dn = m.group(2).strip()
                cn_match = re.search(r"CN\s*=\s*([^,/]+)", dn)
                cn = cn_match.group(1).strip() if cn_match else dn
                if depth not in chain_entries:
                    chain_entries[depth] = {"depth": depth, "cn": cn, "dn": dn}

        result["chain_info"] = sorted(chain_entries.values(), key=lambda x: x["depth"])

        # Detect PQC KEX: we offered hybrid (x25519_mlkem768) and pure (mlkem768) groups.
        # - HYBRID PQC server (e.g. Google): accepts x25519_mlkem768 with classical cert
        #   → "Cipher is TLS_AES..." + Server Temp Key may show hybrid info
        # - PURE PQC server: accepts mlkem768 with PQC cert
        # - Classical server: falls back to x25519 (last in our list)
        #   → negotiates fine but with classical KEX only
        # Detection: if connected + real cipher + (PQC sig OR hybrid/PQC temp key)
        cipher_negotiated = "Cipher is (NONE)" not in output and "Cipher is " in output
        pqc_sig_detected = bool(result.get("signature_type", ""))

        # Check if Server Temp Key or any output line indicates PQC/hybrid KEX
        server_key_raw = result.get("server_temp_key", "").upper()
        pqc_kex_in_output = any(frag in server_key_raw for frag in ["MLKEM", "KYBER", "ML-KEM"])
        # Also check raw output for groups negotiation hints
        if not pqc_kex_in_output:
            pqc_kex_in_output = any(frag in output.upper() for frag in [
                "X25519_MLKEM768", "X25519MLKEM768", "MLKEM768", "ML-KEM-768",
                "X25519_KYBER768", "KYBER768",
            ])
        result["pqc_kex_negotiated"] = "CONNECTED" in output and cipher_negotiated and (pqc_sig_detected or pqc_kex_in_output)

        sig_algos = result.get("signature_algorithms", [])
        pk_algos = result.get("public_key_algos", [])
        logger.info(f"OQS probe success: sig_algos={sig_algos}, pk_algos={pk_algos}, chain={result.get('chain_info')}, pqc_kex={result.get('pqc_kex_negotiated')}")
        
        # If openssl failed the handshake, we don't have a valid TLS connection
        if "no peer certificate available" in output or "Cipher is (NONE)" in output or "1408F10B:SSL routines:ssl3_get_record:wrong version number" in output or "Connection reset by peer" in output:
            logger.warning(f"OQS probe failed handshake for {host}:{port} - {output[:100]}")
            return None
        
        return result

    except subprocess.TimeoutExpired:
        logger.warning(f"OQS probe timed out for {host}:{port}")
        return None
    except Exception as e:
        logger.warning(f"OQS probe failed for {host}:{port}: {e}")
        return None


# PQC signature type fragments for matching OQS probe output
_PQC_SIG_TYPES = {"mldsa", "ml-dsa", "dilithium", "falcon", "sphincs", "slh-dsa", "fn-dsa"}

def _is_pqc_sig(sig_type: str) -> bool:
    """Check if a signature type string from OQS probe indicates PQC."""
    sig_lower = sig_type.lower().replace("_", "").replace("-", "")
    return any(pqc.replace("-", "").replace("_", "") in sig_lower for pqc in _PQC_SIG_TYPES)


@dataclass
class CipherSuiteInfo:
    name: str
    key_exchange: str
    authentication: str
    encryption: str
    hashing: str
    bits: int = 0


@dataclass
class TLSScanResult:
    target: str
    success: bool = False
    error: Optional[str] = None
    tls_version: Optional[str] = None           # e.g. "TLS 1.3"
    supported_tls_versions: list = field(default_factory=list)
    negotiated_cipher: Optional[str] = None
    version_ciphers: dict = field(default_factory=dict) # version -> list of CipherSuiteInfo dicts
    cipher_suites: list = field(default_factory=list)  # list of CipherSuiteInfo dicts (flattened for legacy support)
    key_exchange: Optional[str] = None
    authentication: Optional[str] = None
    encryption: Optional[str] = None
    hashing: Optional[str] = None
    cert_chain: list = field(default_factory=list)     # from cert_parser
    raw_cert_pem: Optional[str] = None


def parse_cipher_name(cipher_name: str) -> CipherSuiteInfo:
    """Parse a cipher suite name into its components."""
    # Examples: TLS_AES_256_GCM_SHA384, ECDHE-RSA-AES256-GCM-SHA384
    parts = cipher_name.replace("TLS_", "").replace("-", "_").split("_")

    # Key exchange detection
    kex = "Unknown"
    auth = "Unknown"
    enc = "Unknown"
    hsh = "Unknown"
    bits = 0

    name_upper = cipher_name.upper()

    # Key exchange — check PQC/hybrid FIRST to avoid ECDHE/X25519 short-circuiting
    if "MLKEM" in name_upper or "ML_KEM" in name_upper or "KYBER" in name_upper:
        kex = "ML-KEM"
    elif "ECDHE" in name_upper or "ECDH" in name_upper:
        kex = "ECDHE"
    elif "DHE" in name_upper or "EDH" in name_upper:
        kex = "DHE"
    elif "RSA" in name_upper and "ECDHE" not in name_upper and "DHE" not in name_upper:
        kex = "RSA"

    # Authentication
    if "ECDSA" in name_upper:
        auth = "ECDSA"
    elif "RSA" in name_upper:
        auth = "RSA"
    elif "ML_DSA" in name_upper or "DILITHIUM" in name_upper:
        auth = "ML-DSA"
    elif "SLH_DSA" in name_upper or "SPHINCS" in name_upper:
        auth = "SLH-DSA"

    # Encryption + bits
    if "AES_256" in name_upper or "AES256" in name_upper:
        enc = "AES-256-GCM" if "GCM" in name_upper else "AES-256-CBC"
        bits = 256
    elif "AES_128" in name_upper or "AES128" in name_upper:
        enc = "AES-128-GCM" if "GCM" in name_upper else "AES-128-CBC"
        bits = 128
    elif "CHACHA20" in name_upper:
        enc = "ChaCha20-Poly1305"
        bits = 256
    elif "CAMELLIA_256" in name_upper or "CAMELLIA256" in name_upper:
        enc = "CAMELLIA-256-CBC"
        bits = 256
    elif "CAMELLIA_128" in name_upper or "CAMELLIA128" in name_upper:
        enc = "CAMELLIA-128-CBC"
        bits = 128
    elif "ARIA_256" in name_upper or "ARIA256" in name_upper:
        enc = "ARIA-256-GCM" if "GCM" in name_upper else "ARIA-256-CBC"
        bits = 256
    elif "ARIA_128" in name_upper or "ARIA128" in name_upper:
        enc = "ARIA-128-GCM" if "GCM" in name_upper else "ARIA-128-CBC"
        bits = 128
    elif "3DES" in name_upper:

        enc = "3DES"
        bits = 112
    elif "RC4" in name_upper:
        enc = "RC4"
        bits = 128

    # Hashing
    if "SHA384" in name_upper:
        hsh = "SHA-384"
    elif "SHA256" in name_upper:
        hsh = "SHA-256"
    elif "SHA512" in name_upper:
        hsh = "SHA-512"
    elif "SHA1" in name_upper or name_upper.endswith("SHA"):
        hsh = "SHA-1"
    elif "MD5" in name_upper:
        hsh = "MD5"

    return CipherSuiteInfo(
        name=cipher_name,
        key_exchange=kex,
        authentication=auth,
        encryption=enc,
        hashing=hsh,
        bits=bits,
    )


async def scan_target(target: str, timeout: int = 30) -> TLSScanResult:
    """
    Perform a TLS scan on a target URL/host using sslyze.
    Returns TLSScanResult with all cipher suite and TLS data.
    """
    from sslyze import (
        ServerNetworkLocation,
        Scanner,
        ServerScanRequest,
        ScanCommand,
    )
    from sslyze.errors import ServerHostnameCouldNotBeResolved, ConnectionToServerFailed
    from app.engine.cert_parser import parse_certificate_chain
    from urllib.parse import urlparse

    # Extract hostname and port
    parsed_url = urlparse(target if target.startswith(('http://', 'https://')) else f'https://{target}')
    host = parsed_url.hostname or target
    port = parsed_url.port or 443

    result = TLSScanResult(target=target)

    try:
        server_location = ServerNetworkLocation(hostname=host, port=port)
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        all_ciphers = []
        supported_versions = []

        for server_scan_result in scanner.get_results():
            if server_scan_result.scan_result is None:
                # connectivity_error_trace (sslyze ≥6) or connectivity_error (older) — use getattr to be safe
                conn_err = (
                    getattr(server_scan_result, "connectivity_error_trace", None)
                    or getattr(server_scan_result, "connectivity_error", None)
                )
                result.error = f"Scan failed: {type(conn_err).__name__}: {conn_err}" if conn_err else "Scan failed: no result"
                break  # Don't return — fall through to OQS Docker enrichment

            scan_res = server_scan_result.scan_result

            # TLS version and cipher enumeration
            version_map = {
                "ssl_2_0_cipher_suites": "SSL 2.0",
                "ssl_3_0_cipher_suites": "SSL 3.0",
                "tls_1_0_cipher_suites": "TLS 1.0",
                "tls_1_1_cipher_suites": "TLS 1.1",
                "tls_1_2_cipher_suites": "TLS 1.2",
                "tls_1_3_cipher_suites": "TLS 1.3",
            }

            best_version = None
            version_ciphers = {}
            for attr, version_label in version_map.items():
                suite_attempt = getattr(scan_res, attr, None)
                if suite_attempt and suite_attempt.result and suite_attempt.result.is_tls_version_supported:
                    suite_result = suite_attempt.result
                    supported_versions.append(version_label)
                    best_version = version_label
                    version_ciphers[version_label] = []
                    for accepted in suite_result.accepted_cipher_suites:
                        cipher_info = parse_cipher_name(accepted.cipher_suite.name)
                        ci_dict = asdict(cipher_info)
                        version_ciphers[version_label].append(ci_dict)
                        if ci_dict not in all_ciphers:
                            all_ciphers.append(ci_dict)

            result.tls_version = best_version
            result.supported_tls_versions = supported_versions
            result.version_ciphers = version_ciphers
            result.cipher_suites = all_ciphers

            # Set negotiated cipher info from the STRONGEST suite on the BEST supported version.
            # This accurately reflects what a modern client (like Rekshak) would negotiate.
            if best_version and version_ciphers.get(best_version):
                best_version_suites = version_ciphers[best_version]
                
                def score_cipher(c):
                    s = c.get("bits", 0)
                    name = c.get("name", "").upper()
                    # AEAD and modern primitives get high scores
                    if "CHACHA" in name: s += 1000
                    if "GCM" in name: s += 500
                    if "AES256" in name: s += 256
                    if "POLY1305" in name: s += 100
                    # Legacy stuff penalized for selection
                    if "CBC" in name: s -= 2000
                    if "3DES" in name: s -= 5000
                    if "SHA1" in name or "MD5" in name: s -= 3000
                    return s

                # Select best from best (max score)
                best = max(best_version_suites, key=score_cipher)
                result.negotiated_cipher = best["name"]
                result.key_exchange = best["key_exchange"]
                result.authentication = best["authentication"]
                result.encryption = best["encryption"]
                result.hashing = best["hashing"]


            # Ensure the negotiated cipher is represented in the CBOM cipher list
            if result.negotiated_cipher:
                negotiated_entry = {
                    "name": result.negotiated_cipher,
                    "key_exchange": result.key_exchange,
                    "authentication": result.authentication,
                    "encryption": result.encryption,
                    "hashing": result.hashing,
                    "bits": 256
                }
                if negotiated_entry not in result.cipher_suites:
                    result.cipher_suites.insert(0, negotiated_entry)
                if negotiated_entry not in all_ciphers:
                    all_ciphers.insert(0, negotiated_entry)


            # Certificate chain
            cert_attempt = getattr(scan_res, "certificate_info", None)
            if cert_attempt and cert_attempt.result and cert_attempt.result.certificate_deployments:
                deployment = cert_attempt.result.certificate_deployments[0]
                result.cert_chain = parse_certificate_chain(deployment.received_certificate_chain)
                
                # REAL PQC SCANNING: Elevate authentication if leaf certificate uses a PQC OID
                if result.cert_chain and "error" not in result.cert_chain[0]:
                    leaf_sig = result.cert_chain[0].get("signature_algorithm_reference", "").upper()
                    if "ML-DSA" in leaf_sig or "DILITHIUM" in leaf_sig or "SLH-DSA" in leaf_sig or "FALCON" in leaf_sig:
                        result.authentication = leaf_sig.split(" (")[0].strip()

            result.success = True

    except ServerHostnameCouldNotBeResolved:
        result.error = f"Could not resolve hostname: {host}"
    except ConnectionToServerFailed as e:
        result.error = f"Connection failed: {e}"
    except Exception as e:
        result.error = f"Scan error: {str(e)}"
        logger.exception(f"Error scanning {target}")

    # ── OQS Docker Enrichment ────────────────────────────────────────
    # Always run the OQS probe to discover the server's true PQC
    # capability. Dual-stack servers send classical certs to classical
    # clients, so we need OQS to see the PQC side.
    logger.info(f"Running OQS Docker enrichment for {target}...")
    oqs_data = _oqs_probe(host, port)
    if oqs_data:
        sig_type = oqs_data.get("signature_type", "")
        if not _is_pqc_sig(sig_type):
            for algo in oqs_data.get("signature_algorithms", []):
                if _is_pqc_sig(algo):
                    sig_type = algo
                    break
                    
        ciphersuite = oqs_data.get("ciphersuite", "")
        tls_ver = oqs_data.get("tls_version", "")
        server_key = oqs_data.get("server_temp_key", "")

        # Normalize PQC authentication name
        oqs_auth = None
        if _is_pqc_sig(sig_type):
            sig_upper = sig_type.upper().replace("_", "").replace("-", "")
            if "MLDSA44" in sig_upper:
                oqs_auth = "ML-DSA-44"
            elif "MLDSA65" in sig_upper:
                oqs_auth = "ML-DSA-65"
            elif "MLDSA87" in sig_upper:
                oqs_auth = "ML-DSA-87"
            elif "FALCON512" in sig_upper:
                oqs_auth = "Falcon-512"
            elif "FALCON1024" in sig_upper:
                oqs_auth = "Falcon-1024"
            else:
                oqs_auth = sig_type.upper()

        # Normalize PQC key exchange name.
        # In TLS 1.3 the "Server Temp Key" line is absent. Instead we detect PQC KEX
        # by whether the server accepted our hybrid/PQC group offer (pqc_kex_negotiated).
        oqs_kex = None
        if oqs_data.get("pqc_kex_negotiated"):
            # Default to hybrid X25519+ML-KEM-768; refine from server_temp_key if available
            oqs_kex = "X25519_MLKEM768"  # Use hybrid name to preserve full info
        if server_key:
            sk_upper = server_key.upper().replace("-", "").replace("_", "").split(",")[0].strip()
            # Check for hybrid names first (e.g. "X25519MLKEM768")
            if "X25519MLKEM768" in sk_upper or "X25519KYBER768" in sk_upper:
                oqs_kex = "X25519_MLKEM768"
            elif "SECP256R1MLKEM768" in sk_upper:
                oqs_kex = "SecP256r1_MLKEM768"
            elif "X25519MLKEM512" in sk_upper:
                oqs_kex = "X25519_MLKEM512"
            # Then check pure PQC names
            elif "MLKEM512" in sk_upper or "KYBER512" in sk_upper:
                oqs_kex = "ML-KEM-512"
            elif "MLKEM768" in sk_upper or "KYBER768" in sk_upper:
                oqs_kex = "ML-KEM-768"
            elif "MLKEM1024" in sk_upper or "KYBER1024" in sk_upper:
                oqs_kex = "ML-KEM-1024"
            elif "MLKEM" in sk_upper or "KYBER" in sk_upper:
                oqs_kex = "ML-KEM"

        # Build OQS cert chain from depth info.
        # Prefer the 'sigalg' field parsed from the cert-chain block ('a:...sigalg:...'),
        # then fall back to the signature_algorithms list indexed by depth.
        chain_info = oqs_data.get("chain_info", [])
        sig_algos = oqs_data.get("signature_algorithms", [])
        oqs_chain = []
        for entry in chain_info:
            cn = entry.get("cn", "")
            depth = entry.get("depth", 0)
            # Prefer per-entry sigalg (from 'a:PKEY:...; sigalg:...' line in cert chain block)
            cert_sig_raw = entry.get("sigalg", "")
            # Fall back to position-indexed signature_algorithms list
            if not cert_sig_raw and depth < len(sig_algos):
                cert_sig_raw = sig_algos[depth]
            is_pqc_cert = _is_pqc_sig(cert_sig_raw)

            # Normalize the per-cert signature algorithm reference
            if is_pqc_cert:
                sa_upper = cert_sig_raw.upper().replace("-", "").replace("_", "")
                if "MLDSA44" in sa_upper:
                    sig_ref = "ML-DSA-44"
                elif "MLDSA65" in sa_upper:
                    sig_ref = "ML-DSA-65"
                elif "MLDSA87" in sa_upper:
                    sig_ref = "ML-DSA-87"
                elif "FALCON512" in sa_upper:
                    sig_ref = "Falcon-512"
                elif "FALCON1024" in sa_upper:
                    sig_ref = "Falcon-1024"
                else:
                    sig_ref = cert_sig_raw.upper()
            else:
                # Fall back to CN-fragment heuristic for servers with no sig algo in probe
                is_pqc_cn = any(p in cn.lower() for p in ["mldsa", "ml-dsa", "dilithium", "falcon", "sphincs", "slh-dsa"])
                sig_ref = oqs_auth if (is_pqc_cn and oqs_auth) else "RSA"
                is_pqc_cert = is_pqc_cn

            key_len = 0
            if is_pqc_cert:
                key_len = PQC_KEY_SIZES.get(sig_ref, PQC_KEY_SIZES.get(sig_ref.upper(), 1024))
            else:
                key_len = 2048  # Default classical fallback

            oqs_chain.append({
                "name": cn,
                "signature_algorithm_reference": sig_ref,
                "key_algorithm": "PQC" if is_pqc_cert else "RSA",
                "key_length": key_len,
                "asset_type": "certificate",
            })

        if not result.success:
            # sslyze FAILED (PQC-only server) — use OQS data as primary
            result.success = True
            result.error = None
            result.tls_version = tls_ver or "TLS 1.3"
            result.negotiated_cipher = ciphersuite

            cipher_info = parse_cipher_name(ciphersuite) if ciphersuite else None
            result.encryption = cipher_info.encryption if cipher_info else "AES-256-GCM"
            result.hashing = cipher_info.hashing if cipher_info else "SHA-384"

            if oqs_auth:
                result.authentication = oqs_auth
            if oqs_kex:
                result.key_exchange = oqs_kex
            elif server_key:
                result.key_exchange = server_key.split(",")[0].strip()

            result.cert_chain = oqs_chain
            result.cipher_suites = [{
                "name": ciphersuite,
                "key_exchange": result.key_exchange or "Unknown",
                "authentication": result.authentication,
                "encryption": result.encryption,
                "hashing": result.hashing,
                "bits": 256,
            }]

            logger.info(f"OQS primary result for {target}: auth={result.authentication}, kex={result.key_exchange}")

        elif oqs_auth or oqs_kex:
            # sslyze SUCCEEDED (dual-stack) — UPGRADE with OQS PQC data
            # The server supports PQC but sent classical to our client.
            # Upgrade authentication, KEX and cert chain to reflect true capability.
            if oqs_auth:
                result.authentication = oqs_auth
            if oqs_kex:
                result.key_exchange = oqs_kex
            if oqs_chain:
                result.cert_chain = oqs_chain

            # ENRICH cipher_suites so CBOM generator sees PQC in "Algorithms" tab
            pqc_suite = {
                "name": f"PQC_{oqs_kex or 'KEX'}_{oqs_auth or 'AUTH'}_{result.encryption}",
                "key_exchange": oqs_kex or result.key_exchange,
                "authentication": oqs_auth or result.authentication,
                "encryption": result.encryption,
                "hashing": result.hashing,
                "bits": 256,
                "is_pqc": True,
            }
            # Add to top of list as the 'preferred' PQC capability detected
            result.cipher_suites.insert(0, pqc_suite)

            logger.info(f"OQS enrichment upgraded {target}: auth={oqs_auth}, kex={oqs_kex}")

    return result


async def scan_targets_concurrent(targets: list[str], progress_callback=None, max_concurrent: int = 10) -> list[TLSScanResult]:
    """Scan multiple targets concurrently with throttling (FR-08, NFR concurrency)."""
    semaphore = asyncio.Semaphore(max_concurrent)
    results = []

    async def scan_with_semaphore(target: str, idx: int) -> TLSScanResult:
        async with semaphore:
            result = await asyncio.get_event_loop().run_in_executor(None, lambda: asyncio.run(scan_target(target)))
            if progress_callback:
                await progress_callback(idx, len(targets), target, result)
            return result

    tasks = [scan_with_semaphore(t, i) for i, t in enumerate(targets)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r if isinstance(r, TLSScanResult) else TLSScanResult(target=targets[i], error=str(r)) for i, r in enumerate(results)]
