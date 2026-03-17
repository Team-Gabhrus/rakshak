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


class ForgotPasswordRequest(BaseModel):
    email: str


@router.post("/login")
async def login(req: LoginRequest, response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    user = await auth_service.authenticate_user(db, req.username, req.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = auth_service.create_access_token({"sub": str(user.id), "role": user.role.value})

    # Prevent concurrent sessions: store current token
    user.active_session_token = token
    from datetime import datetime
    user.last_login = datetime.utcnow()
    await db.commit()

    await log_event(db, "user_login", f"User {user.username} logged in", user.id, user.username, request.client.host if request.client else None)

    return {"access_token": token, "token_type": "bearer", "role": user.role.value, "username": user.username}


@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    user = await auth_service.get_user_by_email(db, req.email)
    if user:
        token = auth_service.generate_reset_token(req.email)
        user.password_reset_token = token
        await db.commit()
        # In production: send email. For prototype: log.
        import logging
        logging.getLogger(__name__).info(f"Password reset token for {req.email}: {token}")

    # Always return success to prevent email enumeration
    return {"message": "If that email exists, a reset link has been sent."}


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
