#!/usr/bin/env python3
"""
Rakshak Local TLS Test Servers
Spins up 4 HTTPS servers on different ports, each with a different TLS/cipher config.
This gives Rakshak realistic targets with known expected PQC labels.

Port mapping:
  8443 — Strong TLS 1.3   → Expected: quantum_safe   (classical ECDSA KX)
  8444 — Legacy TLS 1.0   → Expected: not_quantum_safe
  8445 — RSA-2048 TLS 1.2 → Expected: not_quantum_safe (RSA KX)
  8446 — Modern ECDSA     → Expected: quantum_safe

Run: python tests/test_servers.py
"""
import ssl
import sys
import threading
import time
import os
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

CERTS_DIR = Path(__file__).parent / "certs"

HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><title>{title}</title></head>
<body>
<h1>🛡️ Rakshak Test Server — {title}</h1>
<p>Server: {desc}</p>
<p>Port: {port}</p>
<p>This endpoint is used for Rakshak scanner testing.</p>
<ul>
  <li>TLS Version: {tls_version}</li>
  <li>Key Exchange: {kex}</li>
  <li>Expected PQC Label: <strong>{label}</strong></li>
</ul>
</body></html>"""


class TestHandler(BaseHTTPRequestHandler):
    server_config = {}

    def do_GET(self):
        cfg = self.server_config
        resp = HTML_TEMPLATE.format(**cfg).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, fmt, *args):
        pass  # suppress default logging


SERVER_CONFIGS = [
    {
        "port": 8443,
        "title": "Strong TLS 1.3 Server",
        "desc": "TLS 1.3 only, AES-256-GCM, ECDSA P-384",
        "tls_version": "TLS 1.3",
        "kex": "ECDHE (P-384)",
        "label": "🟡 quantum_safe",
        "cert_name": "strong_tls13",
        "ssl_config": {
            "protocol": ssl.PROTOCOL_TLS_SERVER,
            "minimum_version": ssl.TLSVersion.TLSv1_3,
        },
    },
    {
        "port": 8444,
        "title": "Legacy TLS 1.0 Server",
        "desc": "TLS 1.0 enabled — weak cipher suites",
        "tls_version": "TLS 1.0",
        "kex": "RSA",
        "label": "🔴 not_quantum_safe",
        "cert_name": "legacy_tls10",
        "ssl_config": {
            "protocol": ssl.PROTOCOL_TLS_SERVER,
            "minimum_version": ssl.TLSVersion.TLSv1,
        },
    },
    {
        "port": 8445,
        "title": "RSA-2048 TLS 1.2 Server",
        "desc": "TLS 1.2, RSA-2048, AES-128-GCM",
        "tls_version": "TLS 1.2",
        "kex": "ECDHE (RSA auth)",
        "label": "🔴 not_quantum_safe",
        "cert_name": "weak_rsa2048",
        "ssl_config": {
            "protocol": ssl.PROTOCOL_TLS_SERVER,
            "minimum_version": ssl.TLSVersion.TLSv1_2,
        },
    },
    {
        "port": 8446,
        "title": "Modern ECDSA TLS 1.3 Server",
        "desc": "TLS 1.3, ECDSA P-256, AES-256-GCM-SHA384",
        "tls_version": "TLS 1.3",
        "kex": "ECDHE (ECDSA P-256)",
        "label": "🟡 quantum_safe",
        "cert_name": "modern_ecdsa",
        "ssl_config": {
            "protocol": ssl.PROTOCOL_TLS_SERVER,
            "minimum_version": ssl.TLSVersion.TLSv1_3,
        },
    },
]


def make_handler(config):
    class Handler(TestHandler):
        server_config = config
    return Handler


def start_server(config):
    cert_name = config["cert_name"]
    cert_file = CERTS_DIR / f"{cert_name}.crt"
    key_file  = CERTS_DIR / f"{cert_name}.key"

    if not cert_file.exists() or not key_file.exists():
        print(f"  [WARN] Certs missing for {cert_name} — run generate_certs.py first")
        return None

    try:
        ctx = ssl.SSLContext(config["ssl_config"]["protocol"])
        ctx.load_cert_chain(str(cert_file), str(key_file))

        min_ver = config["ssl_config"].get("minimum_version", ssl.TLSVersion.TLSv1_2)
        try:
            ctx.minimum_version = min_ver
        except Exception:
            pass  # older SSL may not support TLS 1.0 on some systems

        httpd = HTTPServer(("0.0.0.0", config["port"]), make_handler(config))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        print(f"  ✅ https://localhost:{config['port']} — {config['title']}")
        print(f"     Expected label: {config['label']}")
        return httpd

    except Exception as e:
        print(f"  ❌ Port {config['port']} failed: {e}")
        return None


if __name__ == "__main__":
    print("=" * 60)
    print("  Rakshak Local TLS Test Servers")
    print("=" * 60)
    print()

    # Check certs exist
    if not CERTS_DIR.exists() or not list(CERTS_DIR.glob("*.crt")):
        print("Certificates not found — generating them now...\n")
        import subprocess
        result = subprocess.run([sys.executable, str(Path(__file__).parent / "generate_certs.py")])
        print()

    servers = []
    for cfg in SERVER_CONFIGS:
        httpd = start_server(cfg)
        if httpd:
            servers.append(httpd)

    print()
    print("━" * 60)
    print("  All test servers running. Scan targets:")
    print()
    for cfg in SERVER_CONFIGS:
        cert_file = CERTS_DIR / f"{cfg['cert_name']}.crt"
        if cert_file.exists():
            print(f"  https://localhost:{cfg['port']}")
    print()
    print("  To scan these in Rakshak:")
    print("  1. Open http://localhost:8000")
    print("  2. Click 'New Scan'")
    print("  3. Enter the URLs above (one per line)")
    print("  4. Click 'Start Scan'")
    print()
    print("  Or run the automated test: python tests/run_test_scan.py")
    print()
    print("  Press Ctrl+C to stop")
    print("━" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping servers...")
        for srv in servers:
            srv.shutdown()
