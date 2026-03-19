"""
TLS Scanner using sslyze — performs TLS handshakes and enumerates cipher suites.
Covers FR-02, FR-03, FR-04 (via cert_parser), FR-05 (VPN), FR-06 (API).
"""
import asyncio
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)


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
                return result

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

            # Set negotiated cipher info from best available
            if all_ciphers:
                best = all_ciphers[-1]  # last = highest TLS version ciphers
                result.negotiated_cipher = best["name"]
                result.key_exchange = best["key_exchange"]
                result.authentication = best["authentication"]
                result.encryption = best["encryption"]
                result.hashing = best["hashing"]

            # Certificate chain
            cert_attempt = getattr(scan_res, "certificate_info", None)
            if cert_attempt and cert_attempt.result and cert_attempt.result.certificate_deployments:
                deployment = cert_attempt.result.certificate_deployments[0]
                result.cert_chain = parse_certificate_chain(deployment.received_certificate_chain)

            result.success = True

    except ServerHostnameCouldNotBeResolved:
        result.error = f"Could not resolve hostname: {host}"
    except ConnectionToServerFailed as e:
        result.error = f"Connection failed: {e}"
    except Exception as e:
        result.error = f"Scan error: {str(e)}"
        logger.exception(f"Error scanning {target}")

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
