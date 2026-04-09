"""Auth router — FR-22, FR-23, FR-24, FR-25."""
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.services import auth_service
from app.services.audit_service import log_event
from app.config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class OTPVerifyRequest(BaseModel):
    username: str
    otp: str


class ForgotPasswordRequest(BaseModel):
    email: str


@router.post("/login")
async def login(req: LoginRequest, response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    user = await auth_service.authenticate_user(db, req.username, req.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    import random
    from datetime import datetime, timedelta
    from app.services.email_service import send_report_email
    import asyncio
    import logging

    if user.username in ("admin", "checker"):
        token = auth_service.create_access_token({"sub": str(user.id), "role": user.role.value})
        user.active_session_token = token
        user.last_login = datetime.utcnow()
        await db.commit()
        
        real_ip = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", request.client.host if request.client else "Unknown")).split(",")[0].strip()
        user_agent = request.headers.get("User-Agent", "Unknown Device")
        location = "Local"
        # Can easily extract identical IP lookup from verify-otp into a util if needed, 
        # but for hackathon simple log is sufficient here for bypassed accounts.
        details = f"Browser: {user_agent} | Location: {location} (Bypass 2FA)"
        await log_event(db, "user_login", details, user.id, user.username, real_ip)
        
        return {"access_token": token, "token_type": "bearer", "role": user.role.value, "username": user.username, "require_otp": False}

    otp = str(random.randint(100000, 999999))
    user.otp_code = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    await db.commit()

    email_body = f"Hello {user.username},\n\nYour 6-digit OTP for login is: {otp}\n\nIt expires in 5 minutes.\n\nIf you did not attempt to log in, please secure your account.\n\n— Rakshak Admin"
    try:
        asyncio.create_task(send_report_email(
            to_email=user.email,
            subject="Your Rakshak Login OTP",
            body=email_body
        ))
        logging.getLogger(__name__).info(f"OTP dispatch initiated for {user.email}")
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to dispatch OTP email: {e}")

    return {"message": "OTP sent", "require_otp": True, "username": user.username}


@router.post("/verify-otp")
async def verify_otp(req: OTPVerifyRequest, response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    from app.models.user import User
    from datetime import datetime

    result = await db.execute(select(User).where(User.username == req.username))
    user = result.scalar_one_or_none()

    if not user or not user.otp_code:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP session")

    if user.otp_expiry < datetime.utcnow():
        user.otp_code = None
        user.otp_expiry = None
        await db.commit()
        raise HTTPException(status_code=400, detail="OTP expired. Please log in again.")

    if user.otp_code != req.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP code")

    # Clean up OTP after success
    user.otp_code = None
    user.otp_expiry = None

    token = auth_service.create_access_token({"sub": str(user.id), "role": user.role.value})

    # Prevent concurrent sessions: store current token
    user.active_session_token = token
    from datetime import datetime
    user.last_login = datetime.utcnow()
    await db.commit()

    real_ip = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", request.client.host if request.client else "Unknown")).split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "Unknown Device")
    location = "Local"
    if real_ip not in ("127.0.0.1", "localhost", "0.0.0.0", "::1", "Unknown"):
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"http://ip-api.com/json/{real_ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        location = f"{data.get('city', '')}, {data.get('country', '')}".strip(", ")
        except Exception:
            location = "Unknown Location"
            
    details = f"Browser: {user_agent} | Location: {location}"
    await log_event(db, "user_login", details, user.id, user.username, real_ip)

    return {"access_token": token, "token_type": "bearer", "role": user.role.value, "username": user.username}


@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    user = await auth_service.get_user_by_email(db, req.email)
    if not user:
        raise HTTPException(status_code=404, detail="User does not exist.")

    token = auth_service.generate_reset_token(req.email)
    user.password_reset_token = token
    await db.commit()
    # Dispatch recovery email (FR-23)
    from app.services.email_service import send_report_email
    reset_link = f"{settings.APP_BASE_URL}/reset-password?token={token}"
    email_body = f"Hello,\n\nA password reset was requested for your account.\nPlease use the following token to reset your password:\n\n{token}\n\nLink: {reset_link}\n\nIf you did not request this, please ignore this email.\n\n— Rakshak Admin"
    
    import asyncio
    import logging
    try:
        asyncio.create_task(send_report_email(
            to_email=req.email,
            subject="Rakshak Password Recovery",
            body=email_body
        ))
        logging.getLogger(__name__).info(f"Password reset email dispatched to {req.email}")
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed dispatching email to {req.email}: {e}")

    return {"message": "Password reset link sent."}
@router.post("/reset-password")
async def reset_password(token: str, new_password: str, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    from app.models.user import User
    result = await db.execute(select(User).where(User.password_reset_token == token))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    user.hashed_password = auth_service.hash_password(new_password)
    user.password_reset_token = None
    await db.commit()
    return {"message": "Password reset successful"}


from app.dependencies import require_any_role

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_any_role)
):
    current_user.active_session_token = None
    await db.commit()
    await log_event(
        db, 
        "user_logout", 
        f"User {current_user.username} logged out", 
        current_user.id, 
        current_user.username, 
        request.client.host if request.client else None
    )
    
    # If using cookies
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}
