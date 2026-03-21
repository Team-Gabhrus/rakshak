# PNB CyberSecurity Hackathon 2026 - Presentation Content
**Project Name:** Rakshak
**Team Name:** Team Gabhrus

*Note: The official template lists many points under "Outline" and "Continue..." pages. To make the presentation legible while fulfilling every strict requirement, the content below maps every mandatory question into a logical slide-by-slide breakdown. Be sure to use **Arial, Font Size-14 for main points** and **Arial, Font Size-12 for sub-points** as strictly commanded by the template.*

---

## Slide 1: Title Slide
**Title of Project:** Rakshak: Next-Gen PQC Readiness & Cyber Rating System
*(Provide a clear and concise title for your project)*

**Team Name:** Team Gabhrus

**Team Members Name with Role & Contact Details:**
* Akshat Jiwrajka (Full-Stack & Security Engineer) | [Email/Phone]
* Sheersh Nigam (Backend & ML Engineer) | [Email/Phone]
* Arunangshu Karmakar (UI/UX & Frontend) | [Email/Phone]
* Simarpreet Singh (DevOps & Cloud Engineer) | [Email/Phone]

---

## Slide 2: Problem Statement
**Why does this problem exist?**
* The impending arrival of Cryptographically Relevant Quantum Computers (CRQCs) threatens to break currently used public-key encryption standards like RSA and ECC within the next decade.
* Financial institutions possess sprawling digital infrastructure but lack centralized visibility, tracking Cryptographic Bill of Materials (CBOM) manually through spreadsheets.

**Who is affected by it?**
* Banks (like PNB), financial institutions, and government bodies that process, transit, and store highly sensitive financial and Personally Identifiable Information (PII).

**What are the consequences if it remains unresolved?**
* **"Store Now, Decrypt Later" (SNDL) Attacks:** Threat actors are currently intercepting and hoarding banking data to decrypt it retrospectively once quantum technology matures.
* Massive regulatory penalties for non-compliance with upcoming NIST and BSI Post-Quantum Cryptography (PQC) transition mandates.

---

## Slide 3: Proposed Idea
**What is your idea?**
* **Rakshak** is an automated Post-Quantum Cryptography readiness and cyber-rating platform acting as a continuous single source of truth for an organization's cryptographic posture.

**How does it address the problem?**
* It automatically scans domains and IPs to discover and extract TLS/SSL certificates without manual intervention.
* It dynamically generates a real-time Cryptographic Bill of Materials (CBOM) and evaluates each asset against NIST's PQC standards.

**Why is it innovative or unique?**
* **Proprietary Cyber Rating:** It quantifies abstract cryptographic risks into a tangible, actionable Cyber Health Score (0-100).
* **AI Mitigation Playbooks:** Instead of just reporting vulnerabilities, Rakshak uses LLMs to generate step-by-step IT remediation scripts (e.g., specific OpenSSL commands) to upgrade weak assets to PQC-resistant algorithms (Kyber/Dilithium).

---

## Slide 4: Technical Implementation and Tech Stack used
**Tools, Technologies, or Frameworks:**
* **Backend:** Python, FastAPI (for asynchronous scanning), SQLAlchemy, SQLite.
* **Frontend:** HTML5, Tailwind CSS, Alpine.js (for lightweight reactive UI).
* **Scanners:** SSLyze, custom OpenSSL wrappers, and Sublist3r.
* **Deployment:** Docker, Railway Cloud.

**Architecture Diagram and Dataflow (Three Tier):**
* *(Insert Architecture Diagram Image Here)*
* **Tier 1 (Presentation):** Tailwind/Alpine.js Dashboard visualizing real-time CBOM, Cyber Ratings, and UI alerts.
* **Tier 2 (Application/Logic):** FastAPI orchestrating background network discovery tasks, grading algorithms, and calling LLM APIs for playbook generation.
* **Tier 3 (Data):** Relational Database storing historical scan logs, asset inventories, and user roles.

**Key Features:**
* Continuous Asset Discovery & Extractive Cryptographic Auditing.
* Dynamic CBOM Auto-generation & CSV/PDF Exporting.
* Proprietary PQC Cybersecurity Rating Engine.
* Automated AI-Powered Remediation Playbooks.

---

## Slide 5: Impact, Benefits, Feasibility & Scalability
**Impact and Benefits:**
* **Impact:** Radically improves cybersecurity by immunizing institutional perimeters against SNDL attacks and quantum brute-forcing before Q-Day arrives.
* **Benefits:** 
  * *Who benefits:* Security Analysts, CISOs, DevOps teams, and ultimately the Bank's customers.
  * *Outcomes:* Complete regulatory compliance, massive cost savings by reducing manual multi-week crypto audits into minutes of automated scanning, and ironclad data security.

**Feasibility and Scalability:**
* **Feasibility in Data Center:** Rakshak uses agent-less, network-based scanning. It requires no installations on target endpoints, making it perfectly safe and frictionless to deploy inside a banking Data Center environment.
* **Scalability:** The architecture relies on asynchronous Python tasks (FastAPI/asyncio) and is fully Dockerized, easily scaling horizontally across container orchestration platforms (like Kubernetes) to map millions of subdomains.

---

## Slide 6: Potential Challenges & Prototype / Demo
**Potential Challenges:**
* *Risk 1 (Scanning Overhead):* High-volume IP scanning can trigger internal IDS/IPS alarms or cause latency. 
  * *Mitigation:* Implementation of rate-limiting, off-peak scheduled scanning, and IP whitelisting for Rakshak scanners.
* *Risk 2 (AI Hallucinations):* The LLM could generate incorrect remediation commands in the playbook. 
  * *Mitigation:* Enforced rigid prompt-templating and establishing a "Human-in-the-Loop" requirement before any IT changes are executed.

**Prototype or Demo:**
* **Live Deployed Prototype:** [Insert your Railway/Render deployment link here]
* **Code Repository / GitHub:** [Insert your GitHub repo link here]
* *(Insert UI Screenshot: Rakshak Command Center Dashboard / Cyber Rating Speedometer here)*
* *(Insert UI Screenshot: Asset Discovery & CBOM view here)*

---

## Slide 7: Future Roadmap, Conclusion & Media
**Future Roadmap:**
* **Phase 1 (Next Steps):** Integrate Code Repository and Container/Image scanning to detect hardcoded legacy cryptographic keys in source code.
* **Phase 2 (Long-term Enhancements):** Direct integration with SIEM/SOAR platforms (Splunk, QRadar) for enterprise alert routing.
* **Phase 3:** Automated, zero-downtime certificate rotation directly integrating with AWS/Cloudflare networks.

**Conclusion:**
* Rakshak directly answers the hackathon’s call for resilient financial infrastructure. By targeting the inevitability of the quantum threat today, we transition PNB’s cryptographic posture from reactive to proactive, securing tomorrow's financial integrity.

**Supporting Media:**
* *(Reserve this space to attach any extra data flow diagrams, nanobanana graphics, or a QR code link to a demo video).*
