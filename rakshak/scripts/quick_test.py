import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app.engine.tls_scanner import _oqs_probe

async def main():
    for host in ["google.com", "cloudflare.com"]:
        r = await _oqs_probe(host, 443)
        if r:
            print(f"{host}: group={r.get('verified_kex_group')}, stage={r.get('probe_stage')}, pqc={r.get('pqc_kex_negotiated')}")
        else:
            print(f"{host}: None")

asyncio.run(main())
