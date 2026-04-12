"""Quick test: does the classifier downgrade override PQC label?"""
import sys
sys.path.insert(0, ".")
from app.engine.pqc_classifier import classify

# Simulate google.com: ML-KEM-1024 KEX + ECDSA cert + supports TLS 1.0/1.1
r = classify(
    "ML-KEM-1024", "ECDSA", "AES-256-GCM", "SHA-384",
    [{"name": "*.google.com", "signature_algorithm_reference": "sha256 (1.2.840.113549.1.1.11)"}],
    ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"],
    [],
)
print(f"Label:     {r.label_display}")
print(f"KEX:       {r.kex_status}")
print(f"Downgrade: {r.details.get('downgrade_vulnerability', False)}")
print(f"Reason:    {r.details.get('downgrade_reason', 'N/A')}")
