"""
Performance analysis script for Rakshak bulk scan bottleneck investigation.
Tests each phase of the scan pipeline independently to isolate slowdowns.
"""
import asyncio
import time
import subprocess
import socket
import json
import statistics
import sys
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ─── Load targets ────────────────────────────────────────────────────────────
def load_targets(path="target_list.txt"):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]

def parse_host_port(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return p.hostname, p.port or 443


# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: DNS Resolution Timing
# ═══════════════════════════════════════════════════════════════════════════
def test_dns_resolution(targets, max_targets=30):
    """Measure DNS resolution time for a sample of targets."""
    print("\n" + "="*70)
    print("TEST 1: DNS Resolution Timing")
    print("="*70)
    
    sample = targets[:max_targets]
    timings = []
    failures = 0
    
    for t in sample:
        host, port = parse_host_port(t)
        start = time.perf_counter()
        try:
            socket.getaddrinfo(host, port)
            elapsed = time.perf_counter() - start
            timings.append(elapsed)
        except socket.gaierror:
            elapsed = time.perf_counter() - start
            failures += 1
            timings.append(elapsed)
    
    if timings:
        print(f"  Targets tested:  {len(sample)}")
        print(f"  DNS failures:    {failures}")
        print(f"  Min:             {min(timings):.4f}s")
        print(f"  Max:             {max(timings):.4f}s")
        print(f"  Mean:            {statistics.mean(timings):.4f}s")
        print(f"  Median:          {statistics.median(timings):.4f}s")
        print(f"  Total (serial):  {sum(timings):.4f}s")
        print(f"  Est. 164 serial: {statistics.mean(timings) * 164:.2f}s")
    return timings


# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: TCP Connect Timing
# ═══════════════════════════════════════════════════════════════════════════
def test_tcp_connect(targets, max_targets=30, timeout=5):
    """Measure TCP connect time to each target."""
    print("\n" + "="*70)
    print("TEST 2: TCP Connect Timing")
    print("="*70)
    
    sample = targets[:max_targets]
    timings = []
    failures = 0
    timeouts = 0
    
    for t in sample:
        host, port = parse_host_port(t)
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
            elapsed = time.perf_counter() - start
            timings.append(elapsed)
        except (socket.timeout, TimeoutError):
            elapsed = time.perf_counter() - start
            timeouts += 1
            timings.append(elapsed)
        except Exception:
            elapsed = time.perf_counter() - start
            failures += 1
            timings.append(elapsed)
    
    if timings:
        print(f"  Targets tested:  {len(sample)}")
        print(f"  Timeouts:        {timeouts}")
        print(f"  Failures:        {failures}")
        print(f"  Min:             {min(timings):.4f}s")
        print(f"  Max:             {max(timings):.4f}s")
        print(f"  Mean:            {statistics.mean(timings):.4f}s")
        print(f"  Median:          {statistics.median(timings):.4f}s")
        print(f"  Total (serial):  {sum(timings):.4f}s")
        print(f"  Est. 164 serial: {statistics.mean(timings) * 164:.2f}s")
    return timings


# ═══════════════════════════════════════════════════════════════════════════
# TEST 3: Docker exec overhead (no network, just Docker CLI latency)
# ═══════════════════════════════════════════════════════════════════════════
def test_docker_exec_overhead(iterations=10):
    """Measure Docker exec latency with a trivial command."""
    print("\n" + "="*70)
    print("TEST 3: Docker exec Overhead (trivial command)")
    print("="*70)
    
    timings = []
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            r = subprocess.run(
                ["docker", "exec", "rakshak-oqs-daemon", "echo", "ping"],
                capture_output=True, timeout=10
            )
            elapsed = time.perf_counter() - start
            timings.append(elapsed)
        except Exception as e:
            elapsed = time.perf_counter() - start
            timings.append(elapsed)
            print(f"  Docker exec error: {e}")
    
    if timings:
        print(f"  Iterations:      {iterations}")
        print(f"  Min:             {min(timings):.4f}s")
        print(f"  Max:             {max(timings):.4f}s")
        print(f"  Mean:            {statistics.mean(timings):.4f}s")
        print(f"  Median:          {statistics.median(timings):.4f}s")
    return timings


# ═══════════════════════════════════════════════════════════════════════════
# TEST 4: Single OQS s_client probe timing
# ═══════════════════════════════════════════════════════════════════════════
def test_single_oqs_probe(host="google.com", port=443, timeout=30):
    """Measure a single OQS openssl s_client probe end-to-end."""
    print("\n" + "="*70)
    print(f"TEST 4: Single OQS Probe Timing ({host}:{port})")
    print("="*70)
    
    cmd = [
        "docker", "exec", "-i", "rakshak-oqs-daemon",
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-groups", "X25519MLKEM768:mlkem768:x25519",
        "-showcerts",
    ]
    
    start = time.perf_counter()
    try:
        r = subprocess.run(cmd, input=b"Q\n", capture_output=True, timeout=timeout)
        elapsed = time.perf_counter() - start
        print(f"  Elapsed:         {elapsed:.4f}s")
        print(f"  Return code:     {r.returncode}")
        output = r.stdout.decode("utf-8", errors="replace") + r.stderr.decode("utf-8", errors="replace")
        connected = "CONNECTED" in output
        print(f"  Connected:       {connected}")
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - start
        print(f"  TIMEOUT after {elapsed:.4f}s")
    except Exception as e:
        elapsed = time.perf_counter() - start
        print(f"  ERROR: {e} after {elapsed:.4f}s")
    
    return elapsed


# ═══════════════════════════════════════════════════════════════════════════
# TEST 5: OQS Group Discovery Timing
# ═══════════════════════════════════════════════════════════════════════════
def test_oqs_group_discovery():
    """Measure OQS group discovery (openssl list -kem-algorithms)."""
    print("\n" + "="*70)
    print("TEST 5: OQS Group Discovery Timing")
    print("="*70)
    
    cmd = ["docker", "exec", "-i", "rakshak-oqs-daemon", "openssl", "list", "-kem-algorithms"]
    
    start = time.perf_counter()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15)
        elapsed = time.perf_counter() - start
        output = r.stdout.decode("utf-8", errors="replace")
        lines = [l.strip() for l in output.splitlines() if l.strip() and not l.strip().startswith("#")]
        print(f"  Elapsed:         {elapsed:.4f}s")
        print(f"  Groups found:    {len(lines)}")
    except Exception as e:
        elapsed = time.perf_counter() - start
        print(f"  ERROR: {e} after {elapsed:.4f}s")
    
    return elapsed


# ═══════════════════════════════════════════════════════════════════════════
# TEST 6: Count PQC groups and estimate per-target probe time
# ═══════════════════════════════════════════════════════════════════════════
def test_count_pqc_probes():
    """Count how many single-group probes _oqs_probe does per target."""
    print("\n" + "="*70)
    print("TEST 6: PQC Group Count Analysis (probes per target)")
    print("="*70)
    
    cmd = ["docker", "exec", "-i", "rakshak-oqs-daemon", "openssl", "list", "-kem-algorithms"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15)
        output = r.stdout.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  ERROR: {e}")
        return
    
    pqc_fragments = {"mlkem", "kyber", "frodo", "bike", "hqc", "ntru", "saber", "sike"}
    classical_prefixes = {"x25519", "x448", "p256", "p384", "p521", "secp"}
    
    all_groups = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split("@")[0].strip().split(",")[0].strip()
        if name.startswith("{"):
            parts = name.strip("{}").split(",")
            name = parts[-1].strip() if len(parts) > 1 else parts[0].strip()
        if name:
            all_groups.append(name)
    
    pure_pqc = []
    hybrid = []
    for g in all_groups:
        g_lower = g.lower().replace("-", "").replace("_", "")
        if g_lower == "x25519":
            continue
        is_pqc = any(frag in g_lower for frag in pqc_fragments)
        if not is_pqc:
            continue
        is_hybrid = any(c in g_lower for c in classical_prefixes)
        if is_hybrid:
            hybrid.append(g)
        else:
            pure_pqc.append(g)
    
    total_probes = len(pure_pqc) + len(hybrid) + 1  # +1 for full probe
    
    print(f"  Total OQS groups discovered:  {len(all_groups)}")
    print(f"  Pure PQC groups:              {len(pure_pqc)}")
    print(f"  Hybrid groups:                {len(hybrid)}")
    print(f"  Total single-group probes:    {len(pure_pqc) + len(hybrid)}")
    print(f"  + 1 full probe (showcerts):   +1")
    print(f"  ─────────────────────────────────")
    print(f"  WORST-CASE Docker execs/target: {total_probes}")
    print(f"  (Happens when server rejects ALL PQC groups)")
    print()
    print(f"  Pure PQC groups: {pure_pqc[:10]}{'...' if len(pure_pqc) > 10 else ''}")
    print(f"  Hybrid groups:   {hybrid[:10]}{'...' if len(hybrid) > 10 else ''}")
    
    return pure_pqc, hybrid


# ═══════════════════════════════════════════════════════════════════════════
# TEST 7: Sequential single-group probe timing for a non-PQC server
# ═══════════════════════════════════════════════════════════════════════════
def test_sequential_group_probes(host="example.com", port=443, max_groups=10):
    """Measure time for sequential single-group probes on a non-PQC server
    (this simulates the worst-case scenario in _oqs_probe)."""
    print("\n" + "="*70)
    print(f"TEST 7: Sequential Single-Group Probes ({host}:{port})")
    print("="*70)
    
    # Get the groups first
    cmd = ["docker", "exec", "-i", "rakshak-oqs-daemon", "openssl", "list", "-kem-algorithms"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15)
        output = r.stdout.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  ERROR getting groups: {e}")
        return
    
    pqc_fragments = {"mlkem", "kyber", "frodo", "bike", "hqc", "ntru", "saber", "sike"}
    
    groups = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split("@")[0].strip().split(",")[0].strip()
        if name.startswith("{"):
            parts = name.strip("{}").split(",")
            name = parts[-1].strip() if len(parts) > 1 else parts[0].strip()
        if name:
            g_lower = name.lower().replace("-", "").replace("_", "")
            if any(frag in g_lower for frag in pqc_fragments):
                groups.append(name)
    
    sample_groups = groups[:max_groups]
    print(f"  Testing {len(sample_groups)} groups against {host}:{port}")
    
    timings = []
    overall_start = time.perf_counter()
    
    for g in sample_groups:
        cmd = [
            "docker", "exec", "-i", "rakshak-oqs-daemon",
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-groups", g,
        ]
        start = time.perf_counter()
        try:
            r = subprocess.run(cmd, input=b"Q\n", capture_output=True, timeout=15)
            elapsed = time.perf_counter() - start
            timings.append((g, elapsed))
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - start
            timings.append((g, elapsed))
        except Exception as e:
            elapsed = time.perf_counter() - start
            timings.append((g, elapsed))
    
    overall_elapsed = time.perf_counter() - overall_start
    
    for g, t in timings:
        print(f"  {g:35s}  {t:.4f}s")
    
    times_only = [t for _, t in timings]
    if times_only:
        total_groups = len(groups)
        mean_time = statistics.mean(times_only)
        print(f"\n  Sample mean:       {mean_time:.4f}s per probe")
        print(f"  Sample total:      {overall_elapsed:.4f}s for {len(sample_groups)} probes")
        print(f"  Total PQC groups:  {total_groups}")
        print(f"  Est. full serial:  {mean_time * total_groups:.2f}s for ALL groups (worst case, 1 target)")
        print(f"  Est. 164 targets:  {mean_time * total_groups * 164:.2f}s (serial worst case)")
    
    return timings


# ═══════════════════════════════════════════════════════════════════════════
# TEST 8: SSLyze scan time (single target)
# ═══════════════════════════════════════════════════════════════════════════
def test_sslyze_timing(targets, max_targets=5):
    """Measure SSLyze scan time for a few reachable targets."""
    print("\n" + "="*70)
    print("TEST 8: SSLyze Single-Target Scan Timing")
    print("="*70)
    
    try:
        from sslyze import ServerNetworkLocation, Scanner, ServerScanRequest, ScanCommand
        from sslyze.errors import ServerHostnameCouldNotBeResolved, ConnectionToServerFailed
    except ImportError:
        print("  SSLyze not installed — skipping")
        return
    
    # Pick first few targets that resolve
    reachable = []
    for t in targets:
        host, port = parse_host_port(t)
        try:
            socket.getaddrinfo(host, port)
            reachable.append((t, host, port))
            if len(reachable) >= max_targets:
                break
        except:
            continue
    
    timings = []
    for t, host, port in reachable:
        start = time.perf_counter()
        try:
            loc = ServerNetworkLocation(hostname=host, port=port)
            req = ServerScanRequest(
                server_location=loc,
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
            scanner.queue_scans([req])
            for res in scanner.get_results():
                pass  # consume
            elapsed = time.perf_counter() - start
            timings.append((t, elapsed))
            print(f"  {t:55s}  {elapsed:.4f}s")
        except Exception as e:
            elapsed = time.perf_counter() - start
            timings.append((t, elapsed))
            print(f"  {t:55s}  {elapsed:.4f}s (err: {e})")
    
    if timings:
        times_only = [t for _, t in timings]
        print(f"\n  Mean:       {statistics.mean(times_only):.4f}s")
        print(f"  Est. 164 serial: {statistics.mean(times_only) * 164:.2f}s")
    return timings


# ═══════════════════════════════════════════════════════════════════════════
# TEST 9: Concurrent Docker exec capacity
# ═══════════════════════════════════════════════════════════════════════════
async def test_concurrent_docker_exec(concurrency_levels=[1, 5, 10, 20, 50]):
    """Test how Docker handles concurrent exec commands."""
    print("\n" + "="*70)
    print("TEST 9: Concurrent Docker exec Capacity")
    print("="*70)
    
    async def run_docker_exec():
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", "rakshak-oqs-daemon",
            "openssl", "s_client",
            "-connect", "example.com:443",
            "-servername", "example.com",
            "-groups", "x25519",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=b"Q\n"), timeout=15)
            return True
        except:
            try:
                proc.kill()
            except:
                pass
            return False
    
    for level in concurrency_levels:
        start = time.perf_counter()
        tasks = [run_docker_exec() for _ in range(level)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.perf_counter() - start
        successes = sum(1 for r in results if r is True)
        print(f"  Concurrency={level:3d}:  {elapsed:.4f}s  ({successes}/{level} success)  {elapsed/level:.4f}s/op amortized")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 10: Estimate total scan time breakdown
# ═══════════════════════════════════════════════════════════════════════════
def estimate_total_time(num_targets, docker_overhead_s, dns_mean_s, tcp_mean_s, 
                        sslyze_mean_s, num_pqc_groups, probe_mean_s, 
                        full_probe_s, semaphore_limit=50):
    """Model total scan time."""
    print("\n" + "="*70)
    print("ESTIMATE: Total Scan Time Breakdown")
    print("="*70)
    
    # Per-target costs
    dns_per = dns_mean_s
    tcp_per = tcp_mean_s
    sslyze_per = sslyze_mean_s
    
    # OQS probe worst case: test all PQC groups individually + 1 full probe
    oqs_worst_per = (num_pqc_groups * probe_mean_s) + full_probe_s
    # OQS probe best case (first group matches): 1 probe + 1 full probe
    oqs_best_per = probe_mean_s + full_probe_s
    
    # Reachability check
    reach_per = dns_per + tcp_per
    
    # Total per target
    total_worst_per = reach_per + sslyze_per + oqs_worst_per
    total_best_per = reach_per + sslyze_per + oqs_best_per
    
    # With concurrency (semaphore=50), but bottlenecked by Docker single-daemon
    # Docker can handle ~10 concurrent execs efficiently before slowing down
    effective_docker_concurrency = 10  # empirical estimate
    
    oqs_worst_concurrent = oqs_worst_per * num_targets / effective_docker_concurrency
    oqs_best_concurrent = oqs_best_per * num_targets / effective_docker_concurrency
    
    # SSLyze runs in thread pool, so highly parallel
    sslyze_concurrent = sslyze_per * num_targets / semaphore_limit
    
    print(f"  Targets: {num_targets}")
    print(f"  Semaphore limit: {semaphore_limit}")
    print()
    print(f"  Per-target breakdown (worst case, non-PQC server):")
    print(f"    DNS resolution:          {dns_per:.4f}s")
    print(f"    TCP connect:             {tcp_per:.4f}s")
    print(f"    SSLyze scan:             {sslyze_per:.4f}s")
    print(f"    OQS probes ({num_pqc_groups} groups): {oqs_worst_per:.2f}s  ⚠️ BOTTLENECK")
    print(f"    ────────────────────────────────")
    print(f"    TOTAL per target worst:  {total_worst_per:.2f}s")
    print(f"    TOTAL per target best:   {total_best_per:.2f}s")
    print()
    print(f"  Estimated bulk scan time ({num_targets} targets):")
    print(f"    OQS worst case:          {oqs_worst_concurrent:.0f}s ({oqs_worst_concurrent/60:.1f}m)")
    print(f"    OQS best case:           {oqs_best_concurrent:.0f}s ({oqs_best_concurrent/60:.1f}m)")
    print(f"    SSLyze (parallel @50):   {sslyze_concurrent:.0f}s ({sslyze_concurrent/60:.1f}m)")
    print(f"    ────────────────────────────────")
    print(f"    COMBINED worst case:     {oqs_worst_concurrent + sslyze_concurrent:.0f}s ({(oqs_worst_concurrent + sslyze_concurrent)/60:.1f}m)")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main():
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║      RAKSHAK BULK SCAN PERFORMANCE ANALYSIS                        ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    
    targets = load_targets()
    print(f"\nTotal targets in list: {len(targets)}")
    
    # Run synchronous tests
    dns_timings = test_dns_resolution(targets)
    tcp_timings = test_tcp_connect(targets)
    docker_timings = test_docker_exec_overhead()
    test_oqs_group_discovery()
    group_info = test_count_pqc_probes()
    probe_timings = test_sequential_group_probes()
    test_single_oqs_probe()
    sslyze_timings = test_sslyze_timing(targets, max_targets=3)
    
    # Run async tests
    asyncio.run(test_concurrent_docker_exec())
    
    # Final estimate
    dns_mean = statistics.mean(dns_timings) if dns_timings else 0.1
    tcp_mean = statistics.mean(tcp_timings) if tcp_timings else 0.5
    docker_mean = statistics.mean(docker_timings) if docker_timings else 0.5
    sslyze_mean = statistics.mean([t for _, t in sslyze_timings]) if sslyze_timings else 10.0
    probe_mean = statistics.mean([t for _, t in probe_timings]) if probe_timings else 2.0
    
    num_pqc_groups = 0
    if group_info:
        pure, hybrid = group_info
        num_pqc_groups = len(pure) + len(hybrid)
    
    estimate_total_time(
        num_targets=len(targets),
        docker_overhead_s=docker_mean,
        dns_mean_s=dns_mean,
        tcp_mean_s=tcp_mean,
        sslyze_mean_s=sslyze_mean,
        num_pqc_groups=num_pqc_groups,
        probe_mean_s=probe_mean,
        full_probe_s=probe_mean * 1.5,  # full probe is slightly slower
        semaphore_limit=50,
    )
    
    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)


if __name__ == "__main__":
    main()
