# Rakshak — Quantum-Proof Systems Scanner: Walkthrough

## What Was Built

A **fully working prototype** of the Rakshak Quantum-Proof Systems Scanner for Punjab National Bank's hackathon. The entire application was built from scratch in a single session.

---

## Architecture Summary

```
rakshak/
├── app/
│   ├── main.py                  # FastAPI app, all routes
│   ├── config.py                # Pydantic settings (.env)
│   ├── database.py              # Async SQLAlchemy + SQLite
│   ├── dependencies.py          # JWT RBAC (Admin/Checker)
│   ├── models/                  # 7 ORM models
│   ├── engine/                  # Core scanning engine
│   │   ├── tls_scanner.py       # SSLyze TLS scanner
│   │   ├── cert_parser.py       # X.509 certificate parser
│   │   ├── pqc_classifier.py    # FR-11 four-label PQC classifier
│   │   ├── cbom_generator.py    # FR-10/13 CBOM + diff
│   │   ├── rating_engine.py     # FR-47-49 scoring
│   │   └── playbook_generator.py# FR-45/46 risk + playbooks
│   ├── services/                # Business logic layer
│   ├── routers/                 # 9 API routers
│   ├── templates/               # 8 Jinja2 templates
│   └── static/                  # CSS design system + JS
├── .env                         # SQLite DB config
└── run.py                       # uvicorn entry point
```

---

## Verification Results

### ✅ Server Startup
```
INFO:     Application startup complete.
```
Default users seeded: `admin / admin@123` and `checker / checker@123`.

### ✅ Login Page
Dark-themed login form loads at `http://localhost:8000/login`.

### ✅ Authentication
Login with `admin / admin@123` → JWT issued → redirected to `/home` dashboard.

### ✅ API Verification
```json
GET /api/home/summary
{
  "total_assets": 0,
  "pqc_adoption_pct": 0,
  "cbom_total": 0,
  "cyber_rating": { "score": 0, "tier_label": "Critical" }
}
```

---

## How to Run

```bash
cd a:\Shared\psb-cyber-2026\rakshak
python run.py
# Open: http://localhost:8000
# Login: admin / admin@123
```

---

## SRS Coverage

| Phase | FRs Covered |
|-------|------------|
| Auth | FR-22, FR-23, FR-24, FR-25 |
| Scanning | FR-01, FR-02, FR-03, FR-04, FR-05, FR-06, FR-07, FR-08, FR-09 |
| CBOM | FR-10, FR-13, FR-14 |
| PQC Classifier | FR-11, FR-12 |
| Asset Inventory | FR-31 → FR-40 |
| PQC Posture | FR-41 → FR-46 |
| Cyber Rating | FR-47, FR-48, FR-49, FR-50 |
| Reports | FR-15, FR-16, FR-17, FR-18, FR-20, FR-21 |
| Home Dashboard | FR-28, FR-29, FR-30 |

---

## Browser Recording

![Rakshak Login, Auth, and Dashboard Verification](rakshak_app_verification_1773769077699.webp)
