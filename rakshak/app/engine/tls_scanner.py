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

# ── OQS Docker Fallback Probe ───────────────────────────────────────
OQS_DOCKER_IMAGE = "openquantumsafe/curl:latest"

def _docker_available() -> bool:
    """Check if Docker CLI is available."""
    return shutil.which("docker") is not None

def _oqs_probe(host: str, port: int, timeout: int = 30) -> Optional[dict]:
    """
    Use the OQS Docker container to probe a PQC-enabled server.
    Parses openssl s_client -brief output for Signature type, Server Temp Key, etc.
    Returns dict with parsed fields or None on failure.
    """
    if not _docker_available():
        logger.warning("Docker not available — skipping OQS probe")
        return None

    try:
        cmd = [
            "docker", "run", "--rm", "-i",
            OQS_DOCKER_IMAGE,
            "openssl", "s_client", "-connect", f"{host}:{port}", "-brief",
        ]
        logger.info(f"OQS probe cmd: {' '.join(cmd)}")
        proc = subprocess.run(
            cmd, input=b"Q\n", capture_output=True, timeout=timeout,
        )
        output = (proc.stdout.decode("utf-8", errors="replace") +
                  proc.stderr.decode("utf-8", errors="replace"))
        logger.info(f"OQS probe raw output for {host}:{port}:\n{output[:500]}")

        if "CONNECTION ESTABLISHED" not in output:
            logger.info(f"OQS probe to {host}:{port} did not establish connection")
            return None

        result = {}

        # Parse key fields from -brief output
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Signature type:"):
                result["signature_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Server Temp Key:"):
                result["server_temp_key"] = line.split(":", 1)[1].strip()
            elif line.startswith("Ciphersuite:"):
                result["ciphersuite"] = line.split(":", 1)[1].strip()
            elif line.startswith("Protocol version:"):
                result["tls_version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Peer certificate:"):
                result["peer_cert"] = line.split(":", 1)[1].strip()

        # Parse intermediate CA CN from depth lines (e.g., "depth=1 CN=oqstest_intermediate_mldsa44")
        chain_sigs = []
        for line in output.splitlines():
            m = re.search(r"depth=(\d+)\s+CN=(\S+)", line)
            if m:
                depth = int(m.group(1))
                cn = m.group(2)
                chain_sigs.append({"depth": depth, "cn": cn})

        result["chain_info"] = sorted(chain_sigs, key=lambda x: x["depth"])

        logger.info(f"OQS probe success for {host}:{port}: sig={result.get('signature_type')}")
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
    cipher_suites: list = field(default_factory=list)  # list of CipherSuiteInfo dicts
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

    # Key exchange
    if "ECDHE" in name_upper or "ECDH" in name_upper:
        kex = "ECDHE"
    elif "DHE" in name_upper or "EDH" in name_upper:
        kex = "DHE"
    elif "RSA" in name_upper and "ECDHE" not in name_upper and "DHE" not in name_upper:
        kex = "RSA"
    elif "ML_KEM" in name_upper or "KYBER" in name_upper:
        kex = "ML-KEM"
    elif "MLKEM" in name_upper:
        kex = "ML-KEM"

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
                result.error = "Scan failed: no result"
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
            for attr, version_label in version_map.items():
                suite_attempt = getattr(scan_res, attr, None)
                if suite_attempt and suite_attempt.result and suite_attempt.result.is_tls_version_supported:
                    suite_result = suite_attempt.result
                    supported_versions.append(version_label)
                    best_version = version_label
                    for accepted in suite_result.accepted_cipher_suites:
                        cipher_info = parse_cipher_name(accepted.cipher_suite.name)
                        all_ciphers.append(asdict(cipher_info))

            result.tls_version = best_version
            result.supported_tls_versions = supported_versions
            result.cipher_suites = all_ciphers

            # Set negotiated cipher info from weakest available (strict posture check)
            if all_ciphers:
                def score_cipher(c):
                    s = c.get("bits", 0)
                    name = c.get("name", "").upper()
                    if "CHACHA" in name: s += 256  # Prioritize ChaCha20 equivalently to 256-bit
                    if "GCM" in name: s += 10      # Prioritize AEAD (GCM) over CBC
                    return s

                # Grade based on the weakest cipher supported (downgrade attack vulnerability)
                best = min(all_ciphers, key=score_cipher)
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
        ciphersuite = oqs_data.get("ciphersuite", "")
        tls_ver = oqs_data.get("tls_version", "")
        server_key = oqs_data.get("server_temp_key", "")

        # Normalize PQC authentication name
        oqs_auth = None
        if _is_pqc_sig(sig_type):
            sig_upper = sig_type.upper().replace("_", "")
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

        # Build OQS cert chain from depth info
        chain_info = oqs_data.get("chain_info", [])
        oqs_chain = []
        for entry in chain_info:
            cn = entry.get("cn", "")
            is_pqc_cn = any(p in cn.lower() for p in ["mldsa", "ml-dsa", "dilithium", "falcon", "sphincs", "slh-dsa"])
            sig_ref = oqs_auth if is_pqc_cn else "RSA"
            oqs_chain.append({
                "name": cn,
                "signature_algorithm_reference": sig_ref,
                "key_algorithm": "PQC" if is_pqc_cn else "RSA",
                "key_length": 0,
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
            if server_key:
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

            logger.info(f"OQS primary result for {target}: auth={result.authentication}")

        elif oqs_auth:
            # sslyze SUCCEEDED (dual-stack) — UPGRADE with OQS PQC data
            # The server supports PQC but sent classical to our client.
            # Upgrade authentication and cert chain to reflect true capability.
            result.authentication = oqs_auth
            if oqs_chain:
                result.cert_chain = oqs_chain

            logger.info(f"OQS enrichment upgraded {target}: auth={oqs_auth}")

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
