# 🛡️ Rakshak: Next-Gen PQC Readiness & Cyber Rating System

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Docker deployed](https://img.shields.io/badge/Deployed_on-Railway-0B0D0E?style=for-the-badge&logo=railway&logoColor=white)](https://railway.app/)

> **Built for the PNB CyberSecurity Hackathon 2026 by Team Gabhrus**

Rakshak is an automated Post-Quantum Cryptography (PQC) readiness and cyber-rating platform. It acts as a continuous single source of truth for an organization's cryptographic posture, preparing financial institutions against "Store Now, Decrypt Later" (SNDL) attacks and the eventual capabilities of Cryptographically Relevant Quantum Computers (CRQCs).

## ✨ Key Features

1. **Automated Asset Discovery:** Continuously maps assets (Domains, IPs) and comprehensively scrapes x.509 SSL/TLS certificates without manual intervention.
2. **Dynamic CBOM Generation:** Instantly inventories all cryptographic assets (keys, hashing algorithms, cipher suites, expiration dates) and exports them (CSV/PDF) for compliance.
3. **Proprietary Cyber Rating:** Evaluates networks against NIST PQC standards and assigns a proactive "Rakshak Health Score" (0-100) indicating current vulnerability.
4. **AI Mitigation Playbooks:** Uses LLMs to generate step-by-step IT remediation scripts (e.g., specific OpenSSL commands) to upgrade weak legacy assets to PQC-resistant algorithms (like Kyber/Dilithium).

## 🛠️ Technology Stack

* **Backend:** Python, FastAPI (Asynchronous scanning), SQLAlchemy, SQLite
* **Frontend:** HTML5, Tailwind CSS, Alpine.js / Vanilla JS
* **Security & Scanning:** SSLyze, Sublist3r, Python `cryptography`
* **Deployment:** Docker, Railway Cloud

## 🚀 Running Rakshak Locally

### Prerequisites
* Python 3.11+
* OpenSSL installed on your system

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Team-Gabhrus/psb-cyber-26.git
   cd psb-cyber-26/rakshak
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables:**
   Copy the example `.env` file and configure your API keys (e.g., for AI playbook generation).
   ```bash
   cp .env.example .env
   ```

5. **Run the FastAPI server:**
   ```bash
   python run.py
   # OR
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

6. **Access the application:**
   Open your browser and navigate to `http://localhost:8000/`. Default credentials are usually set upon first run (e.g., `admin` / `admin@123`).

## 🐳 Docker Deployment

To build and run the application using Docker:

```bash
docker build -t rakshak-app .
docker run -p 8000:8000 -v rakshak_data:/app/rakshak/data rakshak-app
```

## �� Team Gabhrus

* **Akshat Jiwrajka** - Full-Stack & Security Engineer
* **Sheersh Nigam** - Backend & ML Engineer
* **Arunangshu Karmakar** - UI/UX & Frontend Engineer
* **Simarpreet Singh** - DevOps & Cloud Engineer

---
*Securing today's critical financial assets against tomorrow's quantum threats.*
