"""User registration endpoint — FR-22."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models.user import UserRole
from app.services.auth_service import create_user, get_user_by_email

# This is attached directly in main.py to /api/auth/register


class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str
    role: str = "checker"


async def register_user_endpoint(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await get_user_by_email(db, req.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    try:
        role = UserRole(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role. Use 'admin' or 'checker'")
    user = await create_user(db, req.email, req.username, req.password, role)
    return {"id": user.id, "email": user.email, "username": user.username, "role": user.role.value}
