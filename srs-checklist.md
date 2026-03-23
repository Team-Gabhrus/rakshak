Based on the **Quantum-Proof Systems Scanner (Rakshak)** Software Requirement Specification (SRS) document you shared, here is a comprehensive checklist of everything you need to verify to ensure the current state of the app exactly matches the specified requirements. 

I've categorized the items by functional modules and system features for easier verification:

### 1. Authentication & Access Control (FR-22 to FR-26)
- [ ] **Login screen** exists and explicitly requires an email/username and password.
- [ ] **Forgot Password** functionality exists and sends an email for account recovery.
- [ ] **Role-Based Access Control (RBAC):**
  - **Admin** role has full access (add targets, schedule scans, manage users).
  - **Checker** role has strict read-only access (can only view reports/dashboards).
- [ ] **Session Management:** JWT tokens expire (default 30 mins), automatic timeout on inactivity, and prevention of concurrent sessions for the same user.
- [ ] **Audit Logs:** System accurately logs user login/logouts, scan status, report generations, asset changes, etc. with Timestamp, User ID, and IP address.

### 2. Core Scanning Engine & Input Capabilities (FR-01 to FR-09)
- [ ] Accepts **URLs, IPs, TLS-based VPNs, and API endpoints**.
- [ ] Has **Input Validation** that rejects malformed entries with clear error messages.
- [ ] Supports **Bulk Target Import** (CSV or JSON).
- [ ] Scanning engine accurately connects and extracts:
  - TLS Protocol versions (1.0, 1.1, 1.2, 1.3).
  - Cipher suites (key exchange, auth, encryption, hashing).
  - Parsed Certificate Details (issuer, subject, signature algorithm, public key algorithm, key length, validity, chain).
- [ ] **WebSocket-based Real-Time Scan Monitoring** is visible in the UI (showing phases, per-target status, and ETA).

### 3. PQC Analysis, Labeling & Remediation (FR-11, FR-12, FR-41 to FR-46)
- [ ] Automatically categorizes each component against NIST PQC standards (FIPS 203/204/205).
- [ ] Correctly applies the 4 **Color-coded Labels**:
  - 🔴 **Not Quantum-Safe**
  - 🟡 **Quantum-Safe**
  - 🔵 **PQC Ready**
  - 🟢 **Fully Quantum Safe**
- [ ] Generates specific **Actionable Recommendations** for failing assets (e.g., "Upgrade key exchange from ECDHE to ML-KEM").
- [ ] Features **Automated PQC Migration Playbooks** (step-by-step guides).
- [ ] Displays a **Quantum Risk Timeline** visualizing exposure to "Harvest Now, Decrypt Later (HNDL)" threats.

### 4. CBOM Engine (FR-10, FR-13, FR-14)
- [ ] Generates a Cryptographic Bill of Materials mapped identically to **CERT-IN Annexure-A** minimum elements:
  - Algorithms, Keys, Protocols, and Certificates.
- [ ] **CBOM Snapshot Comparison:** Can select two dates/scans and view a specific "diff" of what has changed.
- [ ] **Interactive Certificate Chain Graph:** Clicking an asset shows a visual tree of the cert chain, color-coded at each step by quantum-safety status.

### 5. UI/UX & Dashboards (FR-27 to FR-50)
- [ ] **Global UI:** Persistent Sidebar, Date/Time Filter, Notifications bell, and Global Search (searching domains, URLs, IPs).
- [ ] **Home Dashboard:** Shows total asset counts, PQC adoption % (circular dial), CBOM vulnerability counts, Cyber Rating breakdown widget.
- [ ] **Asset Inventory:**
  - Visual charts: Asset types, IP Version (IPv4/v6) breakdown, Risk levels, Expiring Certificates timeline.
  - Searchable/sortable table of all assets. "Add Asset" modal and "Scan All" buttons work.
  - Nameserver records sub-table exists.
- [ ] **Asset Discovery:**
  - Categorized tabs (Domains, SSL, IPs, Software).
  - Status filters (New, False Positive, Confirmed, All).
  - **Visual Network Topology Graph** maps connections between IPs, certs, and domains visually.
- [ ] **PQC Posture Tab:** Assets are bucketed into Elite-PQC Ready, Standard, Legacy, and Critical.
- [ ] **Cyber Rating Tab:**
  - Displays a large visual **Gauge/Dial** out of 1000.
  - Shows the **Tier 1 - 4 Compliance Matrix**.
  - Shows a **Historical Trend Line Chart** tracking the score over time.

### 6. Reporting & Notifications (FR-15 to FR-21)
- [ ] Supports **On-Demand** and **Scheduled** reports (Daily/Weekly/Monthly).
- [ ] Users can specifically toggle which modules to include in the report.
- [ ] Can export as **JSON, XML, CSV**, and **PDF** (with optional password protection and charts).
- [ ] Delivery options include configurations for **Email, Local Directory**, and **Slack/Webhook Notification**.

### 7. Under-the-Hood / Technical Requirements (from Sec 2.5 & 4)
- [ ] Backend provides REST API endpoints corresponding exactly to Section 3.2.3 (e.g., `/api/scan/bulk-import`, `/api/cbom/compare`, etc.).
- [ ] Target scanning behaves passively (no payloads, just TLS handshakes).
- [ ] **Dynamic Scan Throttling** exists (adjusts handshake velocity to avoid triggering external WAFs).
- [ ] Scans of single endpoints reliably complete in **under 30 seconds**.
- [ ] Dashboard is fluid (UI loads in < 3 seconds).

**To do a full audit:** You should walk through the app using these points. Since your team built `rakshak` via a FastAPI backend and a frontend design (as seen in your previous conversation context), you'll want to deploy the app locally, boot up both the Admin and Checker logins, run a scan against test targets, and manually verify that every single interactive graph, label, and export format functions exactly as intended above.