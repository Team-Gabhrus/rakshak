"""
Test PQC endpoint reachability to ensure the proposed 'intranet_only' / 'dns_failed'
detection logic would NOT misclassify known PQC servers.

Targets:
  scans.rakshak.live:4433  — rakshak PQC test server A
  scans.rakshak.live:4434  — rakshak PQC test server B
  test.openquantumsafe.org:6182 — OQS public test server

The key question: does TCP connect succeed for these?
If yes, they would correctly go through the full scan path (sslyze fails, OQS probe succeeds)
and never be labelled 'intranet_only'.

Output written to pqc_reach_test.md
"""
import socket, ssl, time, sys, subprocess, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGETS = [
    ("scans.rakshak.live",       4433),
    ("scans.rakshak.live",       4434),
    ("test.openquantumsafe.org", 6182),
]
TCP_TO = 8
TLS_TO = 10

OUTPUT = "pqc_reach_test.md"


def tcp_check(host, port):
    t = time.time()
    try:
        with socket.create_connection((host, port), timeout=TCP_TO): pass
        return True, int((time.time()-t)*1000), ""
    except Exception as e:
        return False, int((time.time()-t)*1000), str(e)


def tls_stdlib_check(host, port):
    """Try TLS with no cert verification (PQC servers use self-signed certs)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = time.time()
    try:
        with socket.create_connection((host, port), timeout=TLS_TO) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ts:
                return True, int((time.time()-t)*1000), f"{ts.version()} / {ts.cipher()[0]}"
    except Exception as e:
        return False, int((time.time()-t)*1000), str(e)


def dns_check(host):
    try:
        ips = list(set(ai[4][0] for ai in socket.getaddrinfo(host, None)))
        return True, ips
    except Exception as e:
        return False, [str(e)]


def oqs_probe_check(host, port):
    """Run the OQS Docker probe (same logic as tls_scanner._oqs_probe)."""
    if not shutil.which("docker"):
        return None, "Docker not available"
    try:
        cmd = ["docker", "run", "--rm", "-i", "openquantumsafe/curl:latest",
               "openssl", "s_client", "-connect", f"{host}:{port}",
               "-showcerts", "-groups", "mlkem768"]
        proc = subprocess.run(cmd, input=b"Q\n", capture_output=True, timeout=35)
        out = proc.stdout.decode("utf-8", errors="replace") + proc.stderr.decode("utf-8", errors="replace")
        connected = "CONNECTED" in out
        cipher_ok = "Cipher is (NONE)" not in out and "Cipher is " in out

        # Extract cipher, protocol, sig type
        cipher = sig = proto = ""
        for line in out.splitlines():
            s = line.strip()
            if "Cipher is " in s:
                import re; m = re.search(r"Cipher is (\S+)", s)
                if m: cipher = m.group(1)
            if "Protocol" in s and "TLS" in s:
                import re; m = re.search(r"Protocol\s*:\s*(\S+)", s)
                if m: proto = m.group(1)
            if s.startswith("Peer signature type:") or s.startswith("Signature type:"):
                sig = s.split(":", 1)[1].strip()
            if "Signature Algorithm:" in s and not sig:
                sig = s.split(":", 1)[1].strip()

        pqc_sigs = {"mldsa","ml-dsa","dilithium","falcon","sphincs","slh-dsa","fn-dsa"}
        is_pqc = any(p in sig.lower().replace("_","").replace("-","") for p in
                     {p.replace("-","").replace("_","") for p in pqc_sigs})
        pqc_kex = connected and cipher_ok

        return {
            "connected": connected,
            "cipher": cipher,
            "proto": proto,
            "sig": sig,
            "pqc_kex_negotiated": pqc_kex,
            "pqc_sig_detected": is_pqc,
        }, None
    except subprocess.TimeoutExpired:
        return None, "OQS probe timed out"
    except Exception as e:
        return None, str(e)


def main():
    lines = []
    lines.append("# PQC Endpoint Reachability Test")
    lines.append("")
    lines.append("Verifying proposed `reachability_check` logic won't misclassify PQC servers.")
    lines.append("")
    lines.append("**Key rule**: if TCP connects → host is reachable → never gets `intranet_only`.")
    lines.append("sslyze may still fail, but OQS probe takes over → correct PQC label.")
    lines.append("")

    results = []
    for host, port in TARGETS:
        print(f"Testing {host}:{port} ...", flush=True)
        dns_ok, ips = dns_check(host)
        tcp_ok, tcp_ms, tcp_info = tcp_check(host, port)
        tls_ok, tls_ms, tls_info = tls_stdlib_check(host, port)
        print(f"  DNS={dns_ok} TCP={tcp_ok} TLS={tls_ok}; running OQS probe...", flush=True)
        oqs_data, oqs_err = oqs_probe_check(host, port)
        results.append((host, port, dns_ok, ips, tcp_ok, tcp_ms, tcp_info,
                         tls_ok, tls_ms, tls_info, oqs_data, oqs_err))
        print(f"  Done.", flush=True)

    for (host, port, dns_ok, ips, tcp_ok, tcp_ms, tcp_info,
         tls_ok, tls_ms, tls_info, oqs_data, oqs_err) in results:

        lines.append(f"## `{host}:{port}`")
        lines.append("")
        lines.append(f"| Check | Result | Detail |")
        lines.append(f"|---|---|---|")
        lines.append(f"| DNS | {'✅ OK' if dns_ok else '❌ FAIL'} | {', '.join(ips)} |")
        lines.append(f"| TCP :{port} | {'✅ OK' if tcp_ok else '❌ FAIL'} ({tcp_ms}ms) | {tcp_info or 'connected'} |")
        lines.append(f"| TLS stdlib (no-verify) | {'✅ OK' if tls_ok else '❌ FAIL'} ({tls_ms}ms) | {tls_info} |")

        if oqs_data:
            lines.append(f"| OQS Docker probe | {'✅ CONNECTED' if oqs_data['connected'] else '❌ NOT CONNECTED'} | cipher={oqs_data['cipher']} proto={oqs_data['proto']} |")
            lines.append(f"| OQS PQC KEX | {'✅ Yes' if oqs_data['pqc_kex_negotiated'] else '❌ No'} | ML-KEM group negotiated |")
            lines.append(f"| OQS PQC Sig | {'✅ Yes' if oqs_data['pqc_sig_detected'] else '❌ No'} | sig={oqs_data['sig']} |")
        else:
            lines.append(f"| OQS Docker probe | ❌ ERROR | {oqs_err} |")

        # Decision logic check
        lines.append("")
        lines.append("**Decision (proposed reachability_check):**")
        if not dns_ok:
            label = "`dns_failed`"
            verdict = "✅ Correct — host doesn't exist"
        elif not tcp_ok:
            label = "`intranet_only`"
            verdict = "⚠️ Would be misclassified if this is a PQC server!"
        else:
            label = "`reachable` → proceeds to full scan (sslyze + OQS probe)"
            verdict = "✅ Correct — OQS probe will detect PQC"
        lines.append(f"- Proposed label: {label}")
        lines.append(f"- Verdict: {verdict}")
        lines.append("")

    # Summary
    lines.append("---")
    lines.append("## Summary")
    lines.append("")
    intranet_misclass = [(h,p) for (h,p,_,_,tcp_ok,*_) in results
                          if tcp_ok is False]
    if intranet_misclass:
        lines.append("❌ **PROBLEM**: The following PQC servers would be misclassified as `intranet_only`:")
        for h, p in intranet_misclass:
            lines.append(f"  - `{h}:{p}`")
        lines.append("")
        lines.append("**Fix needed in plan**: Reachability check must use the *custom port* not just port 443.")
        lines.append("The current plan uses port 443 for TCP check —")
        lines.append("PQC servers on non-443 ports would fail TCP check on 443 and get wrongly labeled.")
    else:
        lines.append("✅ **All PQC servers are TCP-reachable** — the `intranet_only` classification is safe.")
        lines.append("None of the known PQC endpoints would be misclassified.")

    lines.append("")
    lines.append("**Conclusion for plan**: The reachability check must use the target's own port,")
    lines.append("not hardcode port 443. `scan_service._scan_single()` already parses the port")
    lines.append("from the URL, so passing that same port to `reachability_check()` is sufficient.")

    output = "\n".join(lines)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(output)
    print(f"\nResults written to {OUTPUT}")


if __name__ == "__main__":
    main()
