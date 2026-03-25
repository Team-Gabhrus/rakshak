# Title of Project
**Rakshak: Enterprise Quantum-Proof Systems Scanner**

# Team Name
Team Gabhrus

# Team Members Name with Role & Contact Details
- **Member 1 Name**, Role, Contact Details
- **Member 2 Name**, Role, Contact Details
- **Member 3 Name**, Role, Contact Details

*(Placeholder: Update with actual names, roles, and emails/phone numbers)*

# PNB’s CyberSecurity Hackathon-2026
An Initiative of Government of India, Ministry of Finance, Department of Financial Services

---

# Outline

## Problem Statement

### Why does this problem exist? 
The advent of Cryptanalytically Relevant Quantum Computers (CRQCs) threatens the foundational security of current public-key cryptography (like RSA and ECC). Adversaries are already employing "Harvest Now, Decrypt Later" (HNDL) strategies—intercepting and storing encrypted sensitive data today with the intention of decrypting it once quantum computers become powerful enough.

### Who is affected by it?
Financial institutions like Punjab National Bank (PNB), government bodies, and enterprise organizations that handle highly sensitive financial, personal, and classified information are directly at risk. Any entity relying on classical cryptographic protocols (e.g., TLS 1.2/1.3 with RSA/ECDSA) to secure data in transit over the internet is vulnerable.

### What are the consequences if it remains unresolved?
If left unresolved, a CRQC breach would completely compromise data confidentiality, integrity, and authentication. Passwords, financial transactions, and classified communications captured today will be exposed. Furthermore, the inability to verify digital signatures could lead to severe trust breakdowns, massive regulatory penalties, and catastrophic financial losses.

## Proposed Idea

### What is your idea?
**Rakshak** is an automated, enterprise-grade Post-Quantum Cryptography (PQC) scanner and dashboard. It discovers public-facing assets, scans them for their currently deployed cryptographic suites, analyzes their quantum-readiness against NIST standards (FIPS 203, 204, 205), and generates detailed Migration Playbooks.

### How does it address the problem?
Rakshak gives organizations immediate visibility into their quantum risk exposure. Instead of relying on manual audits, Rakshak provides an automated Cryptographic Bill of Materials (CBOM) for every asset. By grading assets on a "PQC Ready" to "Critical" scale and providing step-by-step remediation playbooks, it translates abstract quantum threats into actionable, trackable migration workflows.

### Why is it innovative or unique?
While conventional vulnerability scanners look for known CVEs or misconfigurations, Rakshak is specifically engineered for the cryptographic landscape. It uses specialized hybrid scanning—combining standard OpenSSL/sslyze testing with a custom **OQS (Open Quantum Safe) Docker Probe**. This containerized probe is capable of negotiating experimental post-quantum algorithms (like ML-KEM and ML-DSA) that standard operating systems cannot yet speak, allowing Rakshak to accurately verify if an endpoint is truly quantum-safe.

## Technical Implementation

### Tools, Technologies, or Frameworks:
- **Backend**: FastAPI (Python), SQLAlchemy (SQLite/PostgreSQL)
- **Frontend**: Bootstrap 5, Jinja2 Templates, Vanilla JS, Chart.js, HTML5 Canvas (for Force-Directed Network Topology)
- **Scanning Engine**: sslyze (Classical TLS), Open Quantum Safe (OQS) OpenSSL 3 provider inside Docker
- **Deployment**: Docker, Railway (Platform-as-a-Service)
- **Reporting**: ReportLab (for high-fidelity offline PDF generation)

### Architecture Diagram and Dataflow:
1. **Discovery / Input**: The user inputs targets (Domains, IPs, CIDRs) via the UI or bulk CSV/JSON.
2. **Orchestration**: FastAPI processes the request and queues background jobs.
3. **Execution**: 
   - **Classical Scan**: `sslyze` queries the endpoint to extract TLS versions, classical cipher suites, and the X.509 certificate chain.
   - **Quantum Probe**: A subprocess spins up the `openquantumsafe/curl` Docker container to perform a handshake using advanced algorithms (e.g., `-curves p256_kyber768`), extracting PQC key exchange and signature data.
4. **Analysis Engine**: The results are parsed by the `cert_parser` and `pqc_classifier`, determining if the asset is Elite, Standard, Legacy, or Critical based on NIST matrix definitions.
5. **Storage & Presentation**: Data is saved to the SQLite DB as a CBOM snapshot. The UI polls the WebSocket/API to update the Cyber Rating, Network Topology Graph, and PQC Posture dashboards dynamically.

### Key Features & Technical Differentiators:
- **Automated CBOM Generation**: Detailed cryptographic inventory mapping Key Exchanges, Authentication, Encryption, and Hashing algorithms per asset.
- **Enterprise Cyber Rating**: A unified 0-1000 score indicating organizational quantum migration progress, plotted over time to track improvement.
- **Actionable Migration Playbooks**: Step-by-step, asset-specific remediation guidance highlighting the exact gap (e.g., "Upgrade Certificate Authentication to ML-DSA").
- **Interactive CBOM Diffs**: Granular comparison between historical snapshots to pinpoint exactly which algorithms, keys, or certs were added or removed between scans.
- **Advanced Asset Discovery & Network Topology**: Proactive discovery of domains and IPs, visualized through a custom, canvas-based **force-directed topology graph** utilizing spring-physics for interactive node clustering.
- **Real-Time WebSockets**: Asynchronous Python (FastAPI/asyncio) background scanning tasks that stream live progress updates to the frontend via WebSockets.
- **Enterprise Integrations**: Built-in **Webhooks** engine capable of triggering Slack/Teams alerts on events like `scan_completeted` or `pqc_label_downgraded`, backed by an immutable Audit Log.
- **High-Fidelity PDF Reporting**: Secure, auto-expiring offline reports rendered via `reportlab` featuring PNB-branded layouts and comprehensive safety tiering.
- **Role-Based Access Control (RBAC)**: Secure multi-operator environment distinguishing between Admin and Viewer privileges for managing scans.
- **Bulk Orchestration**: Frictionless ingestion of hundreds of targets simultaneously via CSV/JSON bulk import capabilities.

## Impact and Benefits

### Impact:
Rakshak will dramatically accelerate the transition to quantum-safe architectures by providing the essential first step: comprehensive visibility. It eliminates blind spots in cryptographic deployments.

### Benefits:
- **For PNB and Enterprises**: Significantly reduces the time and cost required to audit legacy systems. 
- **Outcomes/Advantages**: Proactive protection against HNDL attacks, increased regulatory compliance readiness, and structured management of the complex transition period to hybrid cryptography.

## Feasibility and Scalability

### Feasibility:
Rakshak is highly feasible. It is built entirely on mature open-source technologies (FastAPI, Docker, sslyze) combined with the industry-standard OQS project. It requires no agent installations on the target systems, as it performs non-intrusive external network scanning.

### Scalability:
The architecture utilizes asynchronous Python (asyncio) and background task queues, allowing it to scan hundreds of IP addresses and domains concurrently. The SQLite database can easily be hot-swapped for PostgreSQL for massive enterprise deployments, and the containerized scanning workers can be scaled horizontally across a Kubernetes cluster.

## Potential Challenges

### Potential Risks, Limitations, or Obstacles:
1. **Network Firewalls (WAF/IPS)**: Aggressive scanning may be blocked or throttled by enterprise firewalls.
2. **Evolution of Standards**: NIST standards and OID (Object Identifier) codes for PQC algorithms are still being finalized.
3. **Hardware Overhead**: Firing up Docker containers for the OQS probe per target consumes more memory than raw socket connections.

### Mitigation:
1. **Rate Limiting**: Implementing configurable concurrency limits and sleep intervals between requests.
2. **Dynamic Configuration**: Algorithm definitions and OIDs are decoupled from the core logic, allowing quick updates as NIST finalizes the drafts.
3. **Session Pooling & Native Providers**: Future updates will migrate from invoking a Docker container to utilizing a long-running native Python wrapper around `liboqs`, drastically cutting down overhead.

## Prototype or Demo

- **Live Demo Link:** [Insert Railway URL here] *(Already deployed on Railway)*
- **Source Code / Repository:** [Insert GitHub/GitLab URL here]

*(Note: Ensure the Railway deployment is active and the Docker environment for OQS is properly configured in the Railway build process).*

## Future Roadmap

- **Next Steps**: Implement authenticated scanning for internal network segments and integrate deeply with Active Directory (LDAP) for targeted asset ownership mapping. Add a "Remediation Auto-Fix" module that generates `nginx` or `apache` configuration snippets.
- **Long-term Enhancements**: Build a native `liboqs` Cython extension to eliminate the Docker requirement for scanning, and integrate real-time alerts via Slack/Teams using the Webhooks architecture. Implement Continuous Monitoring schedules rather than manual triggers.

## Conclusion
The threat of quantum computing is not a distant sci-fi scenario but an immediate data-harvesting reality. Team Gabhrus' **Rakshak** provides the essential cryptographic radar that PNB needs to defend its public-facing infrastructure. By combining cutting-edge quantum scanning with intuitive, actionable governance dashboards, Rakshak directly answers the hackathon’s objective: securing today's data against tomorrow's quantum threats.

## Supporting Media (Optional)
*(Insert placeholders or links for: Dashboard Screenshots, Diagram of the Architecture, and a short 2-minute video walkthrough of the PDF reporting and Playbook features).*
