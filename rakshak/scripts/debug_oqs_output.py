"""Debug: Compare composite probe vs single-group probe output for Google."""
import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app.engine.tls_scanner import _docker_exec, ensure_oqs_daemon, _discover_oqs_groups

async def main():
    await ensure_oqs_daemon()
    all_groups = await _discover_oqs_groups()
    
    # Test 1: Composite probe (all groups)
    print("=== Test 1: Composite probe (all groups) ===")
    code, output = await _docker_exec(
        ["openssl", "s_client",
         "-connect", "google.com:443",
         "-servername", "google.com",
         "-showcerts",
         "-groups", all_groups],
        input_data=b"Q\n", timeout=30,
    )
    # Show connection info (skip certs)
    for line in output.splitlines():
        stripped = line.strip()
        if any(k in stripped for k in ["Server Temp Key", "Cipher is", "Protocol", "Supported Groups", 
                                         "Agreed Group", "MLKEM", "mlkem", "Kyber", "kyber",
                                         "Server public key", "New, TLS", "Signature type",
                                         "Peer signing", "Peer signature"]):
            print(f"  {stripped}")
    
    print()
    
    # Test 2: Single-group probe (X25519MLKEM768 only)
    print("=== Test 2: Single-group probe (X25519MLKEM768) ===")
    code2, output2 = await _docker_exec(
        ["openssl", "s_client",
         "-connect", "google.com:443",
         "-servername", "google.com",
         "-groups", "X25519MLKEM768"],
        input_data=b"Q\n", timeout=30,
    )
    for line in output2.splitlines():
        stripped = line.strip()
        if any(k in stripped for k in ["Server Temp Key", "Cipher is", "Protocol", "Supported Groups",
                                         "Agreed Group", "MLKEM", "mlkem", "Kyber", "kyber",
                                         "Server public key", "New, TLS", "Signature type",
                                         "Peer signing", "Peer signature"]):
            print(f"  {stripped}")
    
    print()
    
    # Test 3: Check if composite output contains any PQC-related text
    print("=== Test 3: PQC fragment search in composite output ===")
    frags = ["MLKEM", "KYBER", "ML-KEM", "X25519MLKEM", "X25519_MLKEM", "mlkem", "kyber"]
    for frag in frags:
        found = frag.upper() in output.upper()
        print(f"  '{frag}' in output.upper(): {found}")
    
    print()
    
    # Test 4: Show all connection info lines from composite
    print("=== Test 4: All non-cert lines from composite probe ===")
    in_cert = False
    for line in output.splitlines():
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            continue
        if "-----END CERTIFICATE-----" in line:
            in_cert = False
            continue
        if not in_cert and line.strip():
            print(f"  {line.rstrip()}")

asyncio.run(main())
