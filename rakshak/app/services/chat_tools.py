import json
from sqlalchemy import select, desc
from app.database import AsyncSessionLocal
from app.models.asset import Asset
from app.models.cbom import CBOMSnapshot
from app.models.scan import ScanResult
from app.services.domain_service import list_domain_inventory

async def get_domain_subdomain_inventory(domain: str) -> str:
    """
    Returns a consolidated list of subdomains for a given root domain.
    Use this to list targets, find live vs dead hosts, and see which subdomains are available for deeper analysis.
    Args:
        domain: The root domain (e.g., 'example.com').
    """
    async with AsyncSessionLocal() as db:
        groups = await list_domain_inventory(db, [domain])
        if not groups:
            return f"No inventory found for domain {domain}."
        
        group = groups[0]
        targets = group.get("targets", [])
        dead_hosts = group.get("dead_hosts", [])
        
        inventory = {
            "root_domain": domain,
            "live_targets_count": len(targets),
            "live_targets": [
                {
                    "hostname": t["hostname"],
                    "url": t["url"],
                    "pqc_label": t["pqc_label"],
                    "risk_level": t["risk_level"]
                } for t in targets
            ],
            "dead_subdomains_count": len(dead_hosts),
            "dead_subdomains": dead_hosts[:25]
        }
        return json.dumps(inventory)


async def get_subdomain_detailed_cbom(hostname: str) -> str:
    """
    Returns the full Cryptographic Bill of Materials (CBOM) for a specific subdomain hostname.
    Use this to identify specific algorithms (RSA, ML-KEM, etc.), key types, protocol versions, and certificates.
    Args:
        hostname: The hostname of the target (e.g., 'portal.example.com').
    """
    # Clean hostname to URL if needed
    url = hostname
    if not url.startswith("http"):
        url = f"https://{hostname}"

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(CBOMSnapshot).where(CBOMSnapshot.target_url.like(f"%{hostname}%")).order_by(desc(CBOMSnapshot.created_at)).limit(1)
        )
        cbom = result.scalar_one_or_none()
        
        if not cbom:
            return f"No CBOM data found for {hostname}. Ensure the target has been scanned."
        
        return json.dumps({
            "hostname": hostname,
            "pqc_status": cbom.pqc_label,
            "last_captured": cbom.created_at.isoformat(),
            "algorithms": json.loads(cbom.algorithms_json or "[]"),
            "protocols": json.loads(cbom.protocols_json or "[]"),
            "keys": json.loads(cbom.keys_json or "[]"),
            "certificates": json.loads(cbom.certificates_json or "[]")
        })


async def get_subdomain_remediation_guidance(hostname: str) -> str:
    """
    Returns specific remediation steps and PQC migration playbooks for a subdomain.
    Use this when the user asks how to fix a target, improve its score, or migrate to Quantum-Safe algorithms.
    Args:
        hostname: The hostname of the target (e.g., 'api.example.com').
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScanResult).where(ScanResult.target_url.like(f"%{hostname}%")).order_by(desc(ScanResult.scanned_at)).limit(1)
        )
        scan = result.scalar_one_or_none()
        
        if not scan:
            return f"No scan results found for {hostname}. Remediation advice is unavailable."
        
        return json.dumps({
            "hostname": hostname,
            "vulnerabilities": json.loads(scan.recommendations_json or "[]"),
            "pqc_migration_playbook": json.loads(scan.playbook_json or "{}")
        })
