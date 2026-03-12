# Quantum-Proof Systems Scanner — Team Plan

## Part 1: Concept Summary (Everyone Must Read)

### 1. Cipher Suite
A cipher suite is a bundle of algorithms that two parties (browser + server) agree to use for secure communication. It defines:
- **Key Exchange** — how they share a secret (e.g., ECDHE, RSA)
- **Authentication** — how the server proves identity (e.g., RSA, ECDSA)
- **Encryption** — how data is scrambled (e.g., AES-256-GCM)
- **Hashing** — how integrity is verified (e.g., SHA-384)

Example: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`

### 2. TLS (Transport Layer Security)
TLS creates a secure encrypted tunnel between two parties. Neither anyone in the middle (hackers, ISPs) nor the server admins can decrypt past sessions if ephemeral keys are used (forward secrecy).

| Version | Status |
|---------|--------|
| TLS 1.0 / 1.1 | **Deprecated** — insecure |
| TLS 1.2 | **Acceptable** — if configured well |
| TLS 1.3 | **Recommended** — most secure |

### 3. Quantum Computing Threat
- **Shor's algorithm** on a quantum computer can break RSA and ECC (key exchange & authentication).
- **AES-256** and **SHA-256/384** remain safe (Grover's only halves effective key size).
- **HNDL attack** (Harvest Now, Decrypt Later): Adversaries record encrypted data today to decrypt later when quantum computers mature.

### 4. Post-Quantum Cryptography (PQC)
New algorithms resistant to both classical and quantum attacks, standardized by NIST:

| Algorithm | Standard | Purpose | Math Basis |
|-----------|----------|---------|------------|
| **ML-KEM** (Kyber) | FIPS 203 | Key Exchange | Lattice-based |
| **ML-DSA** (Dilithium) | FIPS 204 | Digital Signatures | Lattice-based |
| **SLH-DSA** (SPHINCS+) | FIPS 205 | Digital Signatures (backup) | Hash-based |

### 5. CBOM (Cryptographic Bill of Materials)
A complete inventory of all cryptographic assets used by an application:
- TLS certificates (issuer, algorithm, key size, expiry)
- TLS version
- Cipher suites supported
- Key exchange algorithms
- Protocols (TLS, IPsec, SSH)
- Keys (size, state, creation date)

CERT-IN defines 4 asset categories in Annexure-A: **Algorithms**, **Keys**, **Protocols**, **Certificates** — each with specific fields we must capture.

### 6. What Our Scanner Does
```
INPUT → SCAN → ANALYZE → OUTPUT

Targets      TLS Handshake     Quantum-Safe      CBOM Report
(URLs,       Extract Crypto    Evaluation        QS Labels
IPs)         Details                             Recommendations
```
- Connect to each public-facing target
- Extract TLS version, cipher suites, certificate details
- Classify each component as quantum-safe or not
- Generate CBOM, labels, and remediation steps

### 7. Tech Stack
- **Language:** Python 3.11+
- **TLS Scanning:** sslyze, ssl/socket
- **Cert Parsing:** cryptography library
- **Web Dashboard:** FastAPI + HTML/CSS/JS (Jinja2 templates)
- **Database:** SQLite or PostgreSQL
- **Reports:** JSON + HTML
- **IDE:** VS Code

---

## Part 2: SRS Task Division (4 People)

The SRS has sections that need to be filled in. Here's who owns what:

---

### Person 1 — Team Lead / Project Owner
**Sections:** Introduction, Overall Description, Declaration

| Section | What to Write |
|---------|---------------|
| **Declaration** | Fill in project name, team name, member details (all 3+1) |
| **Revision History** | Fill version, date, author |
| **1.1 Purpose** | Replace placeholder. Write: "To develop a quantum-proof cryptographic scanner that discovers, inventories, and validates the cryptographic posture of public-facing banking applications against NIST PQC standards." |
| **1.2 Scope** | Already partially filled — review and finalize. Add process flow chart. |
| **1.3 Intended Audience** | Already done — review. |
| **2.1 Product Perspective** | Write how this fits into PNB's security ecosystem. It's a standalone scanner tool that integrates with existing infra. Not replacing anything — adding a new capability. |
| **2.2 Product Functions** | List all major functions: (1) Target input, (2) TLS scanning, (3) Certificate analysis, (4) PQC classification, (5) CBOM generation, (6) Labeling, (7) Recommendations, (8) Dashboard display. |
| **2.3 User Classes** | Fill the table: Admin (full access, schedule scans), Checker (view reports, verify compliance). |

**Deliverable:** Completed Sections 1 and 2 (except 2.4, 2.5, 2.6).

---

### Person 2 — Backend Developer / Architect
**Sections:** Operating Environment, Tech Requirements, Constraints, Assumptions

| Section | What to Write |
|---------|---------------|
| **2.4 Operating Environment** | Server: Linux (Ubuntu 22.04+), OS: Linux/Windows, Database: SQLite/PostgreSQL, Platform: Web (FastAPI), Technology: Python 3.11+, sslyze, cryptography lib, API: REST API |
| **2.5 Design & Implementation Constraints** | Fill each sub-section with real values (not examples): Network (must reach public endpoints, outbound 443), Hosting (deploy on intranet server), Access (RBAC with Admin/Checker roles), Encryption (all dashboard traffic over HTTPS), Performance (handle scanning 50+ targets concurrently), UI (responsive web dashboard) |
| **2.6 Assumptions & Dependencies** | Fill with real values: Browser (Chrome 90+), TLS assumed on all targets, internet connectivity needed, depends on Python 3.11+, sslyze, NIST PQC standards |
| **4.1 Technologies** | Python 3.11+, FastAPI, sslyze, cryptography, Jinja2, HTML/CSS/JS |
| **4.2 IDE** | VS Code |
| **4.3 Database** | SQLite (dev) / PostgreSQL (production) |

**Deliverable:** Completed Sections 2.4, 2.5, 2.6, and 4.

---

### Person 3 — Feature Developer / Analyst
**Sections:** Functional Requirements, System Features, External Interfaces

| Section | What to Write |
|---------|---------------|
| **3.1 Functional Requirements** | List every feature as a numbered requirement: FR-01: System shall accept target URLs/IPs as input. FR-02: System shall perform TLS handshake and extract protocol version. FR-03: System shall enumerate all supported cipher suites. FR-04: System shall extract certificate details (issuer, subject, algorithm, validity, chain). FR-05: System shall classify each cryptographic component as Quantum-Safe or Not. FR-06: System shall generate CBOM per CERT-IN Annexure-A format. FR-07: System shall assign labels (Quantum-Safe / PQC Ready / Not PQC Ready). FR-08: System shall generate remediation recommendations. FR-09: System shall export reports in JSON format. FR-10: System shall display results on a web dashboard with High/Medium/Low ratings. |
| **3.2.1 User Interfaces** | Describe the web dashboard: target input form, scan results table, CBOM detail view, label badges, export buttons. |
| **3.2.2 Hardware Interfaces** | Describe: standard server with network access to public internet on port 443. No special hardware. |
| **3.2.3 Software Interfaces** | Describe: REST API endpoints (POST /scan, GET /results, GET /cbom/{id}), communication via HTTPS, JSON format. |
| **3.3 System Features** | Group FRs into features: (1) Target Management, (2) TLS Scanner Engine, (3) PQC Analysis Engine, (4) CBOM Generator, (5) Dashboard & Reporting. Describe each with description, stimulus/response, and functional requirements. |

**Deliverable:** Completed Sections 3.1, 3.2, and 3.3.

---

### Person 4 — Tester / Security Analyst
**Sections:** Non-functional Requirements, Security Requirements

| Section | What to Write |
|---------|---------------|
| **3.4.1 Performance Requirements** | Scan single target < 30 seconds. Dashboard page load < 3 seconds. Support 50+ concurrent scan targets. Report generation < 5 seconds. |
| **3.4.2 Software Quality Attributes** | Reliability: 99.9% uptime for dashboard. Usability: intuitive UI, no training needed for basic scans. Maintainability: modular codebase, easy to add new PQC algorithms. Portability: runs on Linux and Windows. Scalability: can add more scan workers. |
| **3.4.3 Other Non-functional** | Logging: all scan events logged with timestamp. Compliance: aligns with NIST PQC standards and CERT-IN CBOM guidelines. Localization: English language. |
| **5. Security Requirements** | Fill each bullet with real values: Compatibility (standalone, no impact on existing systems), Audit trails (all scans logged with user ID, timestamp, target, results in DB), Access control (RBAC — Admin schedules scans, Checker views reports), Recoverability (DB backups, stateless scanner can restart), Compliance (NIST FIPS 203/204/205, CERT-IN CBOM), Vulnerabilities (scanner only reads, no write access to targets — passive scanning), Environment (all comms over TLS 1.2+), Cost (open-source stack, minimal infra cost). |

**Deliverable:** Completed Sections 3.4 and 5.

---

## Quick Reference: What's Already Done vs. Needs Work

| Section | Status |
|---------|--------|
| 1.1 Purpose | ⚠️ Has placeholder — needs real text |
| 1.2 Scope | ✅ Partially filled — needs review + flowchart |
| 1.3 Intended Audience | ✅ Done |
| 2.1 Product Perspective | ❌ Empty |
| 2.2 Product Functions | ❌ Empty |
| 2.3 User Classes | ⚠️ Has examples — needs real values |
| 2.4 Operating Environment | ⚠️ Has template — needs real values |
| 2.5 Constraints | ⚠️ Has examples — needs real values |
| 2.6 Assumptions | ⚠️ Has examples — needs real values |
| 3.1 Functional Requirements | ❌ Empty |
| 3.2 External Interfaces | ⚠️ Has examples — needs real values |
| 3.3 System Features | ❌ Empty |
| 3.4 Non-functional Requirements | ❌ Empty |
| 4 Technological Requirements | ⚠️ Has examples — needs real values |
| 5 Security Requirements | ⚠️ Has template — needs real values |
| Annexure-A | ✅ Done (reference only) |
