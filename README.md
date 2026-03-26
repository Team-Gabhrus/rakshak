# 🛡️ Rakshak: Next-Gen PQC Readiness & Cyber Rating System

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-OQS_Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/openquantumsafe/curl)
[![Deployed on AWS EC2](https://img.shields.io/badge/Deployed_on-AWS_EC2-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)](https://rakshak.live)

> **Built by Team Gabhrus** · Live at **[rakshak.live](https://rakshak.live)**

---

## 🌐 Live Demo &nbsp;|&nbsp; 📄 Documentation

| | |
|---|---|
| 🚀 **Live Deployment** | **[https://rakshak.live](https://rakshak.live)** — Running on AWS EC2 · Login: `admin` / `admin@123` |
| 📑 **SRS Document (PDF)** | **[Rakshak v1.0 SRS — Team Gabrus](Rakshak%20v1.0%20SRS%20(Team%20Gabrus)%20Updated.pdf)** — Full Software Requirements Specification v1.0 |

Rakshak is an automated **Post-Quantum Cryptography (PQC) readiness and cyber-rating platform** built for Punjab National Bank. It acts as a continuous single source of truth for an organization's cryptographic posture, preparing financial institutions against "Harvest Now, Decrypt Later" (HNDL) attacks and the eventual capabilities of Cryptographically Relevant Quantum Computers (CRQCs).

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **🔬 Dual-Engine PQC Scanner** | Combines **sslyze** (classical TLS) + **OQS Docker probe** (`openquantumsafe/curl`) to detect ML-DSA, Falcon, SLH-DSA, and ML-KEM from real TLS connections — no mocks or hardcoded data. |
| **📋 Dynamic CBOM Generation** | Inventories all cryptographic assets (cipher suites, X.509 certificate chains, OIDs, key lengths) per CERT-IN Annexure-A and exports them as **JSON, XML, CSV, or PDF** for compliance. |
| **🏷️ 4-Tier PQC Classification** | Classifies every asset as ❌ Not Quantum-Safe, 🟡 Partially Quantum-Safe, 🔵 PQC-Ready, or 🟢 Fully Quantum Safe based on real-time cert-chain OID analysis and cipher suite negotiation. |
| **📊 Cyber Rating (0–1000)** | Computes an enterprise-wide quantum-risk score with tier classification (Tier 1–Tier 4: Elite → Standard → Legacy → Critical). |
| **🗺️ Asset Discovery** | Recursively enumerates DNS, IPs, subnets, and server software for all known assets, with a visual network topology graph. |
| **🛠️ AI Migration Playbooks** | Auto-generates step-by-step remediation playbooks to upgrade weak legacy assets to PQC-resistant algorithms (ML-KEM, ML-DSA). |
| **🔒 Weakest-Link Protocol Downgrade** | Automatically forces a "Critical / Not Quantum-Safe" rating if any legacy protocol (TLS 1.0/1.1, SSL 2.0/3.0) or broken cipher (RC4, 3DES) is detected, preventing false-positive safe ratings. |
| **⏱️ Idle Session Timeout** | Enforces a 30-minute idle timeout (activity-based, not absolute), preventing active users from being prematurely logged out. |
| **🎯 Smart Asset-to-CBOM Routing** | Global search opens the selected asset directly into the latest CBOM snapshot for faster investigation workflows. |
| **🌗 Dark / Light Theme** | Persistent dark/light theme toggle stored per session. |
| **📋 Platform Guide** | Built-in guide page explaining PQC posture definitions, label criteria, and risk levels. |
| **👥 User Management & Audit Logs** | Admin-only RBAC panel to manage Admin/Checker users; tamper-evident audit logs with cryptographic hash per entry. |

---

## 🔍 How PQC Detection Works

Rakshak uses a **dual-engine scanning architecture** to detect PQC usage in real-time:

```
── Scan Pipeline ──────────────────────────────────────────────
🔍 Step 1: User enters target (e.g., test.openquantumsafe.org:6182)
🔒 Step 2: sslyze attempts TLS handshake via system OpenSSL
🐳 Step 3: OQS Docker probe runs — detects PQC signatures via liboqs
🏷️ Step 4: Best result (classical or PQC) is selected
📊 Step 5: Classifier walks cert chain OIDs → assigns label
```

| Engine | What It Detects |
|---|---|
| **sslyze** (Primary) | Classical ciphers (ECDHE, RSA, AES), X.509 cert chain OIDs, TLS versions 1.0–1.3, certificate details |
| **OQS Docker Probe** 🐳 | ML-DSA, Falcon, SLH-DSA signatures; ML-KEM key exchange; PQC cert chain depth via `openquantumsafe/curl` |

> **Why two engines?** Standard OpenSSL cannot negotiate PQC cipher suites or parse PQC certificates. The OQS container bundles `liboqs` + `oqs-provider`, enabling Rakshak to detect PQC from real connections — including dual-stack servers that hide PQC certs from classical clients.

### PQC Classification Decision Tree

| Label | Criteria | Risk |
|---|---|---|
| ❌ **Not Quantum-Safe** | Classical KEX (ECDHE/RSA) with no PQC detected, OR any legacy protocol/broken cipher present (Weakest-Link rule) | Critical |
| 🟡 **Partially Quantum-Safe** | PQC detected in one layer only (KEX or Auth), but not both | High |
| 🔵 **PQC-Ready** | PQC KEX + PQC Auth detected, but at least one cert in the trust chain uses a classical signature OID (legacy Root CA) | Medium |
| 🟢 **Fully Quantum Safe** | Every cert in the full trust chain (leaf → intermediate → root) uses PQC signature OIDs | Low |

> **Important:** X25519 and P-256 are classified as **classical/vulnerable** key exchange algorithms. Only NIST-standardized PQC algorithms (ML-KEM, ML-DSA, SLH-DSA per FIPS 203/204/205) qualify for PQC classification.

---

## 🛠️ Technology Stack

* **Backend:** Python 3.11, FastAPI (async), SQLAlchemy (async), SQLite (dev & production)
* **Frontend:** HTML5, Bootstrap 5, Vanilla JS, Chart.js, Jinja2 templates
* **Security & Scanning:** sslyze, OQS Docker (`openquantumsafe/curl`), Python `cryptography`
* **PQC Detection:** X.509 OID parsing (ML-DSA, Falcon, SLH-DSA), liboqs via Docker
* **Deployment:** Docker + AWS EC2 ([rakshak.live](https://rakshak.live))

---

## 🚀 Running Rakshak Locally

### Prerequisites
* Python 3.11+
* **Docker Desktop** (required for PQC detection via OQS probe)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Team-Gabhrus/psb-cyber-26.git
   cd psb-cyber-26
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r rakshak/requirements.txt
   ```

4. **Pull the OQS Docker image** (one-time, ~300MB):
   ```bash
   docker pull openquantumsafe/curl:latest
   ```

5. **Run the FastAPI server:**
   ```bash
   python run.py
   ```

6. **Access the application:**
   Open `http://localhost:8000/` — Default credentials:
   - Admin: `admin` / `admin@123`
   - Checker: `checker` / `checker@123`

---

## 🐳 Docker Deployment

```bash
# Build the app image
docker build -t rakshak-app .

# Run with Docker socket (required for OQS probe)
docker run -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v rakshak_data:/app/rakshak/data \
  rakshak-app
```

> **Note:** The `-v /var/run/docker.sock` mount enables the OQS Docker probe to launch `openquantumsafe/curl` containers for PQC detection.

---

## 🧪 Testing with Local PQC Servers

You can spawn your own local Post-Quantum test servers using Docker to verify the **🔵 PQC Ready** and **🟢 Fully Quantum Safe** labels in Rakshak.

1. Read the full **[PQC Mini Server Setup Guide](pqc_server_setup.md)** to generate ML-DSA certificates and start the `openquantumsafe/curl` container with exposed ports (`-p 4433:4433 -p 4434:4434`).
2. In the Rakshak UI, use `127.0.0.1:4433` or `127.0.0.1:4434` as your scan targets.
   *(Note: If Rakshak is running inside Docker, use `host.docker.internal:4433` instead of `127.0.0.1`)*.

---

*Securing today's critical financial assets against tomorrow's quantum threats.*
