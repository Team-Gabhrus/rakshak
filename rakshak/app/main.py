"""
Main FastAPI application entry point.
Mounts all routers, initializes DB, serves templates + static files.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import require_admin, require_any_role
from app.models.user import User
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import init_db, get_db
from app.routers import auth, scan, assets, cbom, pqc, rating, reports, webhooks, ws
from app.services.auth_service import create_user
from app.models.user import UserRole

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and seed default admin user on startup."""
    await init_db()
    await seed_default_users()
    logger.info("Rakshak started successfully")
    yield
    logger.info("Rakshak shutting down")


async def seed_default_users():
    """Create default admin + checker users if they don't exist."""
    from app.database import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.user import User

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            await create_user(db, "admin@rakshak.pnb.in", "admin", "admin@123", UserRole.admin)
            await create_user(db, "checker@rakshak.pnb.in", "checker", "checker@123", UserRole.checker)
            logger.info("Default users created: admin / checker")


app = FastAPI(
    title="Rakshak — Quantum-Proof Systems Scanner",
    description="Cryptographic posture scanner for PNB public-facing applications",
    version="1.0.0",
    lifespan=lifespan,
)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

# Include API routers
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(assets.router)
app.include_router(cbom.router)
app.include_router(pqc.router)
app.include_router(rating.router)
app.include_router(reports.router)
app.include_router(webhooks.router)
app.include_router(ws.router)

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Redirect to login on 401 if it's a browser navigation, else return standard JSON."""
    if exc.status_code == 401:
        accept = request.headers.get("accept", "")
        # If it's a direct browser request (like a page load or direct link clicking)
        if "text/html" in accept or "application/xhtml+xml" in accept:
            return RedirectResponse(url="/login")
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

# ─── Page routes (serve Jinja2 templates) ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse(url="/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request})


@app.get("/home", response_class=HTMLResponse)
async def home_page(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})


@app.get("/asset-inventory", response_class=HTMLResponse)
async def asset_inventory_page(request: Request):
    return templates.TemplateResponse("asset_inventory.html", {"request": request})


@app.get("/asset-discovery", response_class=HTMLResponse)
async def asset_discovery_page(request: Request):
    return templates.TemplateResponse("asset_discovery.html", {"request": request})


@app.get("/cbom", response_class=HTMLResponse)
async def cbom_page(request: Request):
    return templates.TemplateResponse("cbom.html", {"request": request})


@app.get("/pqc-posture", response_class=HTMLResponse)
async def pqc_posture_page(request: Request):
    return templates.TemplateResponse("pqc_posture.html", {"request": request})


@app.get("/cyber-rating", response_class=HTMLResponse)
async def cyber_rating_page(request: Request):
    return templates.TemplateResponse("cyber_rating.html", {"request": request})


@app.get("/reporting", response_class=HTMLResponse)
async def reporting_page(request: Request):
    return templates.TemplateResponse("reporting.html", {"request": request})


@app.get("/user-management", response_class=HTMLResponse)
async def user_management_page(request: Request):
    return templates.TemplateResponse("user_management.html", {"request": request})


# ─── User management API routes ──────────────────────────────────────────────

@app.get("/api/users")
async def list_users(
    page: int = 1,
    page_size: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_admin)
):
    from sqlalchemy import select, func
    from app.models.user import User
    total_q = await db.execute(select(func.count(User.id)))
    total = total_q.scalar()
    
    result = await db.execute(select(User).order_by(User.id.asc()).offset((page - 1) * page_size).limit(page_size))
    users = result.scalars().all()
    return {
        "items": [{"id": u.id, "email": u.email, "username": u.username,
                  "role": u.role.value, "is_active": u.is_active, "last_login": u.last_login} for u in users],
        "total": total,
        "page": page,
        "page_size": page_size
    }


@app.post("/api/auth/register")
async def register_endpoint(
    req_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    from app.services.register_service import RegisterRequest, register_user_endpoint
    from fastapi import HTTPException
    try:
        req_model = RegisterRequest(**req_data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))
    return await register_user_endpoint(req_model, db)



@app.get("/api/audit-logs")
async def list_audit_logs(
    page: int = 1,
    page_size: int = 10,
    db: AsyncSession = Depends(get_db)
):
    from sqlalchemy import select, func
    from app.models.audit import AuditLog
    
    total_q = await db.execute(select(func.count(AuditLog.id)))
    total = total_q.scalar()
    
    result = await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).offset((page - 1) * page_size).limit(page_size))
    logs = result.scalars().all()
    return {
        "items": [{"id": l.id, "event_type": l.event_type, "username": l.username,
                  "event_details": l.event_details, "ip_address": l.ip_address,
                  "timestamp": l.timestamp, "log_hash": l.log_hash} for l in logs],
        "total": total,
        "page": page,
        "page_size": page_size
    }


@app.get("/api/home/summary")
async def home_summary(start: str = None, end: str = None, db: AsyncSession = Depends(get_db)):
    """Home overview dashboard data — FR-28."""
    from sqlalchemy import select, func
    from app.models.asset import Asset, PQCLabel
    from app.models.cbom import CBOMSnapshot
    from app.models.scan import Scan
    from app.engine.rating_engine import compute_enterprise_score
    from datetime import datetime

    asset_query = select(Asset)
    cbom_query = select(func.count()).select_from(CBOMSnapshot)

    if start:
        dt_start = datetime.fromisoformat(start)
        asset_query = asset_query.where(Asset.created_at >= dt_start)
        cbom_query = cbom_query.where(CBOMSnapshot.created_at >= dt_start)
    if end:
        dt_end = datetime.fromisoformat(end)
        asset_query = asset_query.where(Asset.created_at <= dt_end)
        cbom_query = cbom_query.where(CBOMSnapshot.created_at <= dt_end)

    result = await db.execute(asset_query)
    assets = result.scalars().all()
    total_assets = len(assets)

    pqc_counts = {
        "fully_quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.fully_quantum_safe),
        "pqc_ready": sum(1 for a in assets if a.pqc_label == PQCLabel.pqc_ready),
        "quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.quantum_safe),
        "not_quantum_safe": sum(1 for a in assets if a.pqc_label == PQCLabel.not_quantum_safe),
        "unknown": sum(1 for a in assets if a.pqc_label == PQCLabel.unknown),
    }
    pqc_adoption_pct = round(
        ((pqc_counts["fully_quantum_safe"] + pqc_counts["pqc_ready"]) / total_assets * 100)
        if total_assets else 0, 1
    )

    cbom_result = await db.execute(cbom_query)
    cbom_count = cbom_result.scalar()

    weak_cbom = pqc_counts["not_quantum_safe"] + pqc_counts["unknown"]
    rating = compute_enterprise_score(pqc_counts)
    
    cbom_query_vuln = cbom_query.where(CBOMSnapshot.is_vulnerable == True) if hasattr(CBOMSnapshot, 'is_vulnerable') else cbom_query
    
    # We will just depend on 'weak_cbom' since we have no complex vulnerability calculation for cboms if missing
    return {
        "total_assets": total_assets,
        "pqc_adoption_pct": pqc_adoption_pct,
        "pqc_breakdown": pqc_counts,
        "cbom_total": cbom_count,
        "cbom_vulnerabilities": weak_cbom,
        "cyber_rating": {"score": rating["score"], "tier": rating.get("tier_name"), "tier_label": rating.get("tier_label")},
        "asset_types": {
            "web_apps": sum(1 for a in assets if str(a.asset_type.value if a.asset_type else "") == "web_app"),
            "apis": sum(1 for a in assets if str(a.asset_type.value if a.asset_type else "") == "api"),
            "vpns": sum(1 for a in assets if str(a.asset_type.value if a.asset_type else "") == "vpn"),
            "servers": sum(1 for a in assets if str(a.asset_type.value if a.asset_type else "") == "server"),
        },
    }
