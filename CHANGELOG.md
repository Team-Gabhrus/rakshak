# Rakshak v1.1 Changelog
**Release Date:** April 4, 2026

## 🚀 Major Features & Enhancements

### Advanced Subdomain Enumeration Engine
- **2-Pass Discovery Engine:** Transformed the subdomain scanner into a fully integrated, automated pipeline.
- **CSP Web Scraping:** Integrated CSP header scraping to extract hidden subdomains precisely from targeted assets.
- **Smart Permutations:** Built a permutations generator that leverages confirmed active domains to generate environment-specific endpoint guesses (dev, api, test, etc.).

### Automated Vulnerability Pipeline
- **Auto-Scan Integration:** Discovered live subdomains are now automatically bundled and injected into the background vulnerability scanner queue upon verification.
- **Inflated Scan Requests:** Manually scanning a root domain via the Dashboard or Inventory page can optionally auto-expand targets to include all discovered subdomains prior to running the primary `sslyze` & Post-Quantum Cryptography probes.

### Modernized Asset Topology UI
- **Hierarchical Domain Collapsing:** Grouped high-volume domains (e.g. hundreds of subdomains belonging to a single parent hostname) into neat accordion rows inside both **Asset Inventory** and **Asset Discovery** components.
- **Intelligent TLD Parsing:** The grouping functionality properly splits TLD suffixes like `.co.uk` and `.bank.in` natively.

### Bulk Interaction Framework
- **Cross-Platform Checkboxes:** Replaced standard confirmations and allowed bulk selections scaling across individual Discovery results and Scan Histories.
- **Live Assets Only Filter:** Equipped the `Asset Discovery` view with a custom frontend filter handling immediate visibility of exclusively 'Live' DNS verified endpoints.
- **Scan Selected Routing:** Directly push arbitrary Discovery domains into active Vulnerability Scans via the bulk-selection modal.

### Traceable Scan Diagnostics
- **Scan Detail Expansion:** Redesigned the "Recent Scans" block in the Dashboard. Selecting a scan unlocks an interactive accordion tracking parallel workers against pending targets alongside categorizing Success and Failed domains.

### Infrastructure & Deployment Resilience
- **Persistent Environment Secrets:** Modernized the `.github/workflows/deploy.yml` configurations with robust host mappings, feeding dynamic `.env` states immediately into Docker run steps.
- **Persistent Disk Solutions:** Handled backend storage mapping against EBS volume exhaustion loops.
