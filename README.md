# 🛡️ Rakshak: Next-Gen PQC Readiness & Cyber Rating System

[![Version 1.1](https://img.shields.io/badge/Version-1.1-A3112E?style=for-the-badge)](https://rakshak.live)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-OQS_Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/openquantumsafe/curl)
[![Gemini AI](https://img.shields.io/badge/Gemini_3.0_Flash-AI_Chat-8E44AD?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev/)
[![Deployed on AWS EC2](https://img.shields.io/badge/Deployed_on-AWS_EC2-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)](https://rakshak.live)

> **Built by Team Gabhrus** · Live at **[rakshak.live](https://rakshak.live)** · **v1.1** (April 2026)

---

## 🌐 Live Demo &nbsp;|&nbsp; 📄 Documentation

| | |
|---|---|
| 🚀 **Live Deployment** | **[https://rakshak.live](https://rakshak.live)** — Running on AWS EC2 · Login: `admin` / `admin@123` |
| 🎬 **Demo Video** | **[Watch on YouTube](https://youtu.be/qE33vVxZ83I)** — Full walkthrough of all platform features |
| 📊 **Presentation (PDF)** | **[Rakshak — Team Gabrus Presentation](Rakshak%20(Team%20Gabrus)%20Presentation.pdf)** — Hackathon pitch deck |
| 📑 **SRS Document (v1.1)** | **[Rakshak v1.1 SRS](Rakshak%20v1.1%20SRS.pdf)** — Full Software Requirements Specification v1.1 |

Rakshak is an automated **Post-Quantum Cryptography (PQC) readiness and cyber-rating platform** built for Punjab National Bank. It acts as a continuous single source of truth for an organization's cryptographic posture, preparing financial institutions against "Harvest Now, Decrypt Later" (HNDL) attacks and the eventual capabilities of Cryptographically Relevant Quantum Computers (CRQCs).

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **🔬 Dual-Engine PQC Scanner** | Combines **sslyze** (classical TLS) + **OQS Docker probe** (`openquantumsafe/curl`) to detect ML-DSA, Falcon, SLH-DSA, and ML-KEM from real TLS connections — no mocks or hardcoded data. |
| **🤖 Rakshak AI Chat Assistant** | Domain-aware conversational AI powered by **Google Gemini 3.0 Flash** for interactive vulnerability analysis, PQC migration guidance, and domain intelligence queries — with domain context injection, copy/retry actions, and security-focused dynamic "thinking" indicators. |
| **🌐 Advanced Subdomain Discovery** | Multi-source enumeration engine using **CSP header scraping**, **DNS brute-force wordlists**, and **smart permutation generation** with real-time WebSocket progress streaming. Auto-injects live subdomains into the scan queue. |
| **🔐 Two-Factor Authentication (2FA)** | Email-based OTP verification on login — 6-digit codes with 5-minute expiry, protecting all user sessions beyond standard credentials. |
| **📋 Dynamic CBOM Generation** | Inventories all cryptographic assets (cipher suites, X.509 certificate chains, OIDs, key lengths) per CERT-IN Annexure-A and exports them as **JSON, XML, CSV, or PDF** with domain-scoped filtering and per-target CBOM history. |
| **🏷️ 6-Tier PQC Classification** | Classifies every asset as ❌ Not Quantum-Safe, 🟡 Partially Quantum-Safe, 🔵 PQC-Ready, 🟢 Fully Quantum Safe, ⚫ Intranet-Only, or ⬛ DNS Failed — based on real-time cert-chain OID analysis and target reachability. |
| **📊 Cyber Rating (0–1000)** | Computes an enterprise-wide quantum-risk score with tier classification (Tier 1–4) and individual per-asset cyber score drill-downs. |
| **🗺️ Domain-Driven Asset Management** | Groups assets by root domain in collapsible accordion views, supports "Scan Selected" bulk operations, and cascading bulk delete with automatic cleanup of linked records (scans, CBOM, chat sessions, discovery records). |
| **🛠️ AI Migration Playbooks** | Auto-generates step-by-step remediation playbooks to upgrade weak legacy assets to PQC-resistant algorithms (ML-KEM, ML-DSA). |
| **🔒 Weakest-Link Protocol Downgrade** | Automatically forces a "Critical / Not Quantum-Safe" rating if any legacy protocol (TLS 1.0/1.1, SSL 2.0/3.0) or broken cipher (RC4, 3DES) is detected, preventing false-positive safe ratings. |
| **⏱️ Scan Lifecycle Management** | Full scan state machine (Queued → Running → Cancelling → Cancelled/Completed/Failed) with per-target diagnostic breakdowns and real-time cancellation support. |
| **📑 Domain-Scoped Reporting** | PDF reports with domain-wise summary sections, subdomain coverage tables, and per-domain target breakdowns alongside standard module-based reports. |
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
| ⚫ **Intranet-Only** | DNS resolves but port is firewalled / intranet-only — no cryptographic assessment possible | N/A |
| ⬛ **DNS Failed** | Hostname does not resolve in public DNS — target may be decommissioned or internal-only | N/A |

> **Important:** X25519 and P-256 are classified as **classical/vulnerable** key exchange algorithms. Only NIST-standardized PQC algorithms (ML-KEM, ML-DSA, SLH-DSA per FIPS 203/204/205) qualify for PQC classification.

---

## 🛠️ Technology Stack

* **Backend:** Python 3.11, FastAPI (async), SQLAlchemy (async), SQLite (dev & production)
* **Frontend:** HTML5, Bootstrap 5, Vanilla JS, Chart.js, Jinja2 templates
* **AI:** Google Gemini 3.0 Flash (via `google-genai` SDK) — domain-aware chat assistant with context injection
* **Security & Scanning:** sslyze, OQS Docker (`openquantumsafe/curl`), Python `cryptography`, email-based 2FA (OTP)
* **PQC Detection:** X.509 OID parsing (ML-DSA, Falcon, SLH-DSA), liboqs via Docker
* **Subdomain Discovery:** Multi-source enumeration (CSP scraping, DNS brute-force, permutation generation) with WebSocket progress
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

6. **Set environment variables** (for AI Chat and 2FA):
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   export SMTP_HOST="smtp.example.com"  # For OTP emails
   export SMTP_USER="user@example.com"
   export SMTP_PASS="your-smtp-password"
   ```

7. **Access the application:**
   Open `http://localhost:8000/` — Default credentials:
   - Admin: `admin` / `admin@123`
   - Checker: `checker` / `checker@123`
   
   > **Note:** Default demo accounts bypass 2FA OTP for evaluation. Production accounts require email OTP verification.

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

## 📋 What's New in v1.1

- 🤖 **Rakshak AI Chat Assistant** — Domain-aware conversational AI powered by Gemini 3.0 Flash
- 🔐 **Two-Factor Authentication** — Email-based OTP verification on all logins
- 🌐 **Advanced Subdomain Discovery** — CSP scraping, DNS brute-force, permutation generation with real-time WebSocket progress
- 🗂️ **Domain-Driven Scanning** — Root domain grouping, collapsible accordion UI, "Scan Selected" bulk operations
- ⏹️ **Scan Cancellation** — Full lifecycle management with state machine and per-target diagnostics
- 🏷️ **New PQC Labels** — `Intranet-Only` and `DNS Failed` for firewalled/unreachable assets
- 📑 **Domain-Scoped Reporting** — PDF reports with domain-wise summary sections and subdomain tables
- 📊 **Individual Asset Scores** — Per-asset cyber score drill-down on the Cyber Rating page
- 🧹 **Cascading Asset Cleanup** — Bulk delete with automatic removal of linked scans, CBOM, chat history
- 🔍 **CBOM Domain Filtering** — Filter snapshots by root domain with per-target history view

---

*Securing today's critical financial assets against tomorrow's quantum threats.*
