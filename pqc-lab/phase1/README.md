# PQC Lab - Phase 1 (Environment Setup)

This phase prepares a local, reproducible environment for PQC certificate/server experiments using the Open Quantum Safe (OQS) Docker image.

## What Phase 1 does
- Creates a working directory for generated certs and test artifacts.
- Verifies Docker availability.
- Launches an interactive OQS shell with volume mount to your local workspace.

## Folder structure
- `workspace/`: shared directory mounted into container at `/opt/test`.
- `verify_prereqs.sh`: checks Docker daemon and image availability.
- `enter_oqs_shell.sh`: launches OQS container shell.

## Quick start
From repo root:

```bash
chmod +x pqc-lab/phase1/*.sh
./pqc-lab/phase1/verify_prereqs.sh
./pqc-lab/phase1/enter_oqs_shell.sh
```

Inside container, verify PQC-capable OpenSSL:

```bash
openssl version -a
openssl list -public-key-algorithms | grep -Ei 'mldsa|dilithium|kyber|mlkem' || true
```

If that works, Phase 1 is complete and we move to certificate generation in Phase 2.

## Notes
- This setup is designed for macOS + Docker Desktop.
- If Docker Desktop is not running, start it and rerun `verify_prereqs.sh`.
