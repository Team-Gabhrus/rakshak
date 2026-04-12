"""
Quick reachability scan: classify all 164 targets as reachable / dns_failed / timeout.
This shows how many targets hit the worst-case 5s TCP timeout path.
"""
import socket
import time
import statistics

def load_targets(path="target_list.txt"):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]

def parse_host_port(url):
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return p.hostname, p.port or 443

def classify(host, port, timeout=5):
    """Returns (status, elapsed)"""
    # DNS
    start = time.perf_counter()
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror:
        return "dns_failed", time.perf_counter() - start
    
    # TCP
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return "reachable", time.perf_counter() - start
    except (socket.timeout, TimeoutError):
        return "timeout", time.perf_counter() - start
    except (ConnectionRefusedError, OSError):
        return "refused", time.perf_counter() - start

targets = load_targets()
results = {"reachable": [], "dns_failed": [], "timeout": [], "refused": []}
timings_by_status = {"reachable": [], "dns_failed": [], "timeout": [], "refused": []}

print(f"Scanning {len(targets)} targets for reachability...\n")

for i, t in enumerate(targets):
    host, port = parse_host_port(t)
    status, elapsed = classify(host, port)
    results[status].append(t)
    timings_by_status[status].append(elapsed)
    print(f"  [{i+1:3d}/{len(targets)}] {status:12s} {elapsed:6.2f}s  {t}")

print("\n" + "="*70)
print("REACHABILITY SUMMARY")
print("="*70)
for status, targets_list in results.items():
    count = len(targets_list)
    total_time = sum(timings_by_status[status])
    mean_time = statistics.mean(timings_by_status[status]) if timings_by_status[status] else 0
    print(f"  {status:12s}: {count:3d} targets  total={total_time:7.2f}s  mean={mean_time:.4f}s")

total = sum(len(v) for v in results.values())
total_time = sum(sum(v) for v in timings_by_status.values())
print(f"  {'─'*55}")
print(f"  {'TOTAL':12s}: {total:3d} targets  total={total_time:7.2f}s")

# Key insight: how much time is wasted on timeouts
timeout_waste = sum(timings_by_status["timeout"])
dns_fail_time = sum(timings_by_status["dns_failed"])
print(f"\n  ⚠️ Time wasted on TCP timeouts: {timeout_waste:.2f}s")
print(f"  ⚠️ Time on DNS failures:        {dns_fail_time:.2f}s")
print(f"  ⚠️ These targets still go through the FULL OQS probe pipeline!")
