import requests
import concurrent.futures
import json
import re
import socket

class PassiveSubdomainAggregator:
    def __init__(self, target_domain):
        self.target = target_domain
        self.subdomains = set()
        # Regex to extract valid subdomains from messy text
        self.regex = re.compile(r'([a-zA-Z0-9.-]+)\.' + re.escape(self.target))
        
        # Setup robust session
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def extract_and_add(self, text):
        """Finds anything matching our target domain in a block of text."""
        clean_text = text.replace('\\n', ' ').replace('\n', ' ')
        
        matches = self.regex.findall(clean_text)
        for match in matches:
            clean_sub = f"{match}.{self.target}".lower().lstrip('*.')
            # Skip wildcards and bare domain
            if '*' not in clean_sub and clean_sub != self.target:
                self.subdomains.add(clean_sub)

    def scrape_crtsh(self):
        print("[*] Querying crt.sh (Certificate Logs)...")
        try:
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                self.extract_and_add(response.text)
                print("[+] crt.sh search complete.")
        except Exception as e:
            print(f"[-] crt.sh failed: {e}")

    def scrape_alienvault(self):
        print("[*] Querying AlienVault OTX (Threat Intel)...")
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
            response = self.session.get(url, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    self.extract_and_add(entry.get('hostname', ''))
                print("[+] AlienVault search complete.")
        except Exception as e:
            print(f"[-] AlienVault failed: {e}")

    def scrape_wayback(self):
        print("[*] Querying Wayback Machine (Web Archives)...")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&collapse=urlkey&fl=original"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                self.extract_and_add(response.text)
                print("[+] Wayback Machine search complete.")
        except Exception as e:
            print(f"[-] Wayback Machine failed: {e}")

    def verify_dns(self, timeout: float = 5.0, max_workers: int = 30) -> tuple:
        """
        Verify which discovered subdomains actually resolve in public DNS.
        Returns:
          live: {hostname: [ip, ...]}  — resolves OK
          dead: [hostname]             — cert ghosts / decommissioned
        """
        def _resolve(host):
            try:
                socket.setdefaulttimeout(timeout)
                ais = socket.getaddrinfo(host, None)
                ips = list(set(ai[4][0] for ai in ais))
                return host, True, ips
            except socket.gaierror:
                return host, False, []
            finally:
                socket.setdefaulttimeout(None)

        live, dead = {}, []
        print(f"\n[*] DNS-verifying {len(self.subdomains)} discovered subdomains...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_resolve, h): h for h in self.subdomains}
            for fut in concurrent.futures.as_completed(futs):
                host, ok, ips = fut.result()
                if ok:
                    live[host] = ips
                else:
                    dead.append(host)
        print(f"[+] DNS verification done: {len(live)} live, {len(dead)} dead (cert ghosts)")
        return live, dead

    def run(self):
        print(f"=== Starting Passive Aggregation for {self.target} ===\n")
        
        methods = [self.scrape_crtsh, self.scrape_alienvault, self.scrape_wayback]
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(method) for method in methods]
            concurrent.futures.wait(futures)

        # DNS verification — filter out cert ghosts
        live, dead = self.verify_dns()

        print("\n==================================================")
        print(f"🎯 FINAL RESULTS FOR {self.target.upper()}")
        print(f"Total Raw Discovered : {len(self.subdomains)}")
        print(f"✅ Live (DNS resolves): {len(live)}")
        print(f"💀 Dead / Cert Ghosts: {len(dead)}")
        print("==================================================")

        print("\n✅ LIVE SUBDOMAINS:")
        for sub, ips in sorted(live.items()):
            print(f"  {sub}  →  {', '.join(ips)}")

        if dead:
            print("\n💀 DEAD / CERT GHOSTS (excluded from scan targets):")
            for sub in sorted(dead):
                print(f"  {sub}")

        return sorted(live.keys())  # return only live subdomains


if __name__ == "__main__":
    target = "manipurrural.bank.in"  # Replace with your target
    scanner = PassiveSubdomainAggregator(target)
    scanner.run()