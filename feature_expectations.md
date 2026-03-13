Here is an exhaustive, structured breakdown of every feature visible in the "POC-Ready pnb" (रक्षण) prototype, organized by its navigation modules to match your problem statement goals! 🕵️‍♀️✨

### 1. Authentication & Global Navigation

* A login screen requiring Email/Username and Password, with a "Forgot Password?" option and a "Sign in" button.


* A persistent sidebar navigation menu including Home, Asset Inventory, Asset Discovery, CBOM, Posture of PQC, Cyber Rating, and Reporting.


* A global search bar to look up domains, URLs, contacts, IoCs, or other assets.


* A Time Period filter to specify start and end dates for the displayed data.



### 2. Home Overview Dashboard

* High-level summary of Assets Discovery showing total domains, IPs, subdomains, and cloud assets.


* A progress indicator for "Posture of PQC" showing the percentage of post-quantum cryptography adoption.


* A summary for CBOM highlighting the number of vulnerable components.


* A Cyber Rating breakdown categorized into Tiers (Excellent, Good, Satisfactory, Needs Improvement).


* An Assets Inventory summary detailing counts of SSL Certificates, Software, IoT Devices, and Login Forms.



### 3. Asset Inventory Module

* Top-level metrics displaying total counts for Public Web Apps, APIs, Servers, and overall Total Assets.


* Visual distribution charts for Asset Risk, Expiring Certificates Timeline, IP Version Breakdown (IPv4 vs IPv6), and Asset Type Distribution (Critical, High, Medium, Low).


* A detailed, searchable data table listing assets with columns for Asset Name, URL, IPv4/IPv6 Address, Type, Owner, Risk, Cert Status, Key Length, and Last Scan time.


* A dedicated section for Nameserver Records displaying Domain, Hostname, IP Address, Type, IPv6 Address, Asset, TTL, Key Length, Cipher Suite TLS, and Certificate Authority.


* Functionality to "Add Asset" and trigger a "Scan All" action.



### 4. Asset Discovery Module

* Categorized discovery tabs for Domains, SSL, IP Address/Subnets, and Software.


* Status filtering options to view New, False Positive/ignore, Confirmed, and All discovered assets.


* Detailed tracking tables for each category, such as Registration Date and Registrar for Domains , Fingerprint and Certificate Authority for SSL , and Location, Subnet, ASN, and Netname for IPs.


* A visual network topology graph mapping the connections between IPs, SSLs, Web servers, Domains, and scanning tags .



### 5. CBOM (Cryptographic Bill of Materials) Module

* Summary metrics for Total applications, Sites Surveyed, Active Certificates, Weak cryptography, and Certificate issues.


* Analytical charts visualizing Cipher Usage (e.g., ECDHE-RSA-AES256-GCM-SHA384), Top Certificate Authorities (e.g., DigiCert, Let's Encrypt), Key Length Distribution (1024 to 4096-bit), and Encryption Protocols (TLS 1.1, TLS 1.2) .


* A granular mapping table detailing the specific Key Length, Cipher, and Certificate Authority used by individual applications.



### 6. Posture of PQC Module

* A PQC Compliance Dashboard categorizing assets into Elite-PQC Ready, Standard, Legacy, and Critical Apps.


* Risk Overview charts and Application Status tracking.


* Actionable "Improvement Recommendations" directly addressing the hackathon's core problem statement, such as upgrading to TLS 1.3 with PQC, implementing Kyber for Key Exchange, updating Cryptographic Libraries, and developing a PQC Migration Plan.


* Detailed individual app profiles showing PQC Support status, Ownership, Exposure level, TLS type, and an assigned Score/Status .



### 7. Cyber Rating Module

* A "Consolidated Enterprise-Level Cyber-Rating Score" displaying an overall dial metric out of 1000.


* A classification table that maps asset status (Legacy, Standard, Elite-PQC) to specific numerical score ranges.


* A comprehensive compliance matrix defining Tier 1 (Elite) through Tier 4 (Critical).


* Definitions for each Tier's Security Level, required Compliance Criteria (like TLS version and cipher strength), and Priority/Action required.



### 8. Reporting Module

* Dual reporting modes: "Scheduled Reporting" for recurring executives reports and "On-Demand Reporting" for immediate needs.


* Configuration options to select Report Type, Frequency (e.g., Weekly), and specific target Assets.


* Checkboxes to dynamically include specific module sections (Discovery, Inventory, CBOM, PQC Posture, Cyber Rating) in the report .


* Detailed scheduling tools including Date, Time, and Time Zone selection .


* Multiple delivery and output settings, including Email routing, Saving to a local directory, Slack Notification, and selecting File Format (like PDF) with options for Password Protection and including charts .



---
