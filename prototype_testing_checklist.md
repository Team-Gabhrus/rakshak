# Prototype Testing Checklist: Quantum-Proof Systems Scanner (Rakshak)

This checklist is an exhaustive list derived directly from the Software Requirement Specification (SRS) document to ensure the Rakshak prototype works perfectly and addresses all required Functional Requirements (FR), System Features (SF), and Non-Functional Requirements.

## 1. Authentication & Access Control (SF-01)
- [x] **Login screen** authenticates valid users and issues JWT tokens (FR-22).
- [x] **Login limits** reject invalid credentials with appropriate error messages.
- [x] **Forgot Password** functionality correctly dispatches a recovery email (FR-23).
- [x] **RBAC (Admin):** Admins can configure targets, schedule scans, and manage users (FR-24).
- [x] **RBAC (Checker):** Checkers have strictly read-only access to view reports and verify compliance (FR-24).
- [x] **Session Management:** JWT expires after elapsed time (default 30 mins) and logs out inactive sessions (FR-25).
- [x] **Audit Logs:** System accurately records user logins, logouts, scan events, and config changes (with user ID, IP, and timestamp) in an immutable format (FR-26).

## 2. Dashboard & Navigation (SF-02)
- [x] **Global Layout:** Persistent sidebar navigation functions across all modules (Home, Asset Inventory, Discovery, CBOM, PQC Posture, Cyber Rating, Reporting) (FR-27).
- [x] **Home Dashboard:** Summary cards display accurate metric counts (assets discovered, PQC adoption %, vulnerabilities, Cyber Rating breakdown) (FR-28).
- [x] **Global Search:** Returns accurate, matching items across domains, URLs, APIs, IPs, and IoCs (FR-29).
- [x] **Time Period Filter:** Correctly updates dashboard data widgets based on user-selected date ranges (FR-30).

## 3. Asset Inventory Management (SF-03)
- [x] **Metrics & visual charts:** Accurately display metrics for Web Apps, APIs, and Servers, including Pie/Donut charts for Risk levels and IPv4/v6 (FR-31, FR-32).
- [x] **Data Table Operations:** The main inventory table is fully sortable and searchable by Asset Name, URL, IP, Risk, Cert Status, Key length, etc. (FR-33).
- [x] **Nameserver records:** Accurately shown for assets (FR-34).
- [x] **Manual Addition:** "Add Asset" modal works properly and queues the new asset for background scanning (FR-35).
- [x] **Trigger Scans:** The "Scan All" action correctly initiates bulk sequential scans across inventoried assets (FR-35).
- [x] **Bulk Import:** CSV/JSON target lists are properly parsed and ingested without errors (FR-36).

## 4. Scan Engine & Execution Engine (SF-04)
- [x] **Asset Categorization:** Appropriately bins assets into Domains, SSL Certificates, IPs/Subnets, and Software (FR-37).
- [x] **Status Filtering:** Can filter assets by New, False Positive/Ignore, Confirmed, and All (FR-38).
- [x] **False Positives:** Users can mark assets to be ignored and excluded from future tracking (FR-38).
- [x] **Discovery Metrics:** Accurate reporting of Registrar, IP location, Subnets, and Netnames (FR-39).
- [x] **Network Topology Graph:** Renders relationships clearly and is interactive (zoomable/draggable) (FR-40).

## 5. Core Scanning Engine (TLS, VPN, API) (SF-05)
- [x] **Input Validation:** Prevents malformed entries (invalid URLs or IPs) and gives user-friendly errors (FR-09).
- [x] **Scan Types:** Successfully accepts inputs for URLs, IPs, API endpoints (REST/SOAP), and TLS-based VPNs (FR-01, FR-05, FR-06).
- [x] **TLS Handshake:** Successfully connects and pulls TLS version (e.g., TLS 1.2, TLS 1.3) (FR-02).
- [x] **Cipher Enumeration:** Correctly extracts all supported cipher suites (key exchange, auth, encryption, hashing) (FR-03).
- [x] **Certificate Analysis:** Accurately extracts issuer, subject, signature/public key algorithm, key length, validity, and full chain details (FR-04).
- [x] **WebSocket Monitoring:** Real-time updates push accurate progress logs and ETA to the UI during active scans (FR-08).

## 6. PQC Analysis & Classification Engine (SF-06)
- [x] **NIST Evaluation:** Evaluates each cryptographic component precisely against FIPS 203/204/205 limits (FR-07).
 - [x] **Labeling (🔴 Not Quantum-Safe):** Applied properly to vulnerable classical algorithms like RSA key exchange or SHA-1 (FR-11).
 - [x] **Labeling (🟡 Quantum-Safe):** Applied if symmetric/hash is safe but key exchange/auth is classical (FR-11).
 - [x] **Labeling (🔵 PQC Ready):** Applied when key exchange or auth is NIST standard (e.g., ML-KEM) while others are classical (FR-11).
 - [x] **Labeling (🟢 Fully Quantum Safe):** Applied when all components are PQC/safe (FR-11).
- [x] **Remediation:** Generates accurate, algorithmic step-by-step recommendation steps (FR-12).
- [x] **Migration Playbooks:** Auto-generates customized templates containing effort and risk estimations (FR-46).
- [x] **Quantum Risk Timeline:** Renders a time graph highlighting when specific algorithms become exposed to HNDL (FR-45).

## 7. CBOM Generator (SF-07)
- [x] **CERT-IN Annexure-A Format:** Strictly validates generated CBOM across all 4 sections (Algorithms, Keys, Protocols, Certificates) with no missing mandatory fields (FR-10).
- [x] **CBOM Visuals:** Graphical distribution of Cipher Usage, Key Lengths, and Encryption protocols is correct (FR-32).
- [x] **Snapshot Comparison:** Can compare dates and accurately output an intuitive "diff" highlighting new, removed, and updated assets (FR-13).
- [x] **Certificate Chain Visualization:** Displays interactive tree mapping with quantum-safety indicators assigned correctly to each node level (FR-14).

## 8. Cyber Rating System (SF-08)
- [x] **Score Generation:** Automatically computes the Consolidated Enterprise-Level Cyber-Rating Score out of 1000 correctly based on assets (FR-47).
- [x] **Status Mapping:** The classification table accurately categorizes results into Tiers (Elite to Critical) (FR-48, FR-49).
- [x] **Historical Trend Line:** Time-series plotting correctly displays upward/downward organizational progress over days/weeks (FR-50).

## 9. Enterprise Reporting & Export (SF-09)
- [x] **Exports Output:** Test downloads for JSON, XML, CSV, and PDF complete successfully (FR-15).
- [x] **PDF Protection:** Configured PDF exports securely require the user-defined password to open and contain graphs/charts (FR-20).
- [x] **On-Demand Reporting:** Selectively includes only the modules chosen in the configuration checks (FR-18).
- [x] **Scheduled Reporting:** Works correctly according to the cron/interval selected (Daily/Weekly/Monthly) (FR-17).
- [x] **Delivery Channels:** Reports reach configured local directories, Emails, and/or Slack webhooks correctly (FR-19).
- [x] **Real-time API Webhooks:** The scanner successfully POSTs to a configured endpoint on critical findings or scan completions (FR-21).

## 10. Non-Functional & System Considerations
- [x] **Execution Speed Limit:** A single target endpoint fully scans in under **30 seconds**.
- [x] **Concurrency Validation:** The core algorithm handles multiple target executions efficiently (aiming toward 50 concurrent scale).
- [x] **Frontend Performance:** Dashboard metrics and UI renders complete within **3 seconds**.
- [x] **Report Execution TTT:** On-demand exports structure and build completely in under **5 seconds**.
- [x] **System Failover Recovery:** If a mock failure is triggered mid-scan, the system restarts cleanly with its last state pulled up safely via the DB without data corruption.
- [x] **Passive Scanning Integrity:** Ensure the scanner does not attempt any payload injection, modify state, or leave residual artifacts on target banking applications.
