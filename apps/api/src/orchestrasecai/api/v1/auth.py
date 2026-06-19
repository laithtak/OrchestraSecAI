from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.deps import get_current_user
from orchestrasecai.api.schemas import LoginRequest, MeResponse, RefreshRequest, TokenResponse, UserOut
from orchestrasecai.config import get_settings
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import Organization, User
from orchestrasecai.security.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.last_login_at = datetime.now(UTC)
    access = create_access_token(str(user.id), str(user.org_id), user.role.value)
    refresh = create_refresh_token(str(user.id))
    request.state.audit_record = {
        "org_id": user.org_id,
        "user_id": user.id,
        "action": "auth.login",
        "resource_type": "user",
        "resource_id": str(user.id),
    }
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        from uuid import UUID

        user_id = UUID(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from None
    user = await db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    access = create_access_token(str(user.id), str(user.org_id), user.role.value)
    refresh_tok = create_refresh_token(str(user.id))
    return TokenResponse(access_token=access, refresh_token=refresh_tok)


@router.get("/me", response_model=MeResponse)
async def me(user: UserOut = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    org = await db.get(Organization, user.org_id)
    return MeResponse(
        user=user,
        org={"id": str(org.id), "name": org.name, "slug": org.slug} if org else {},
    )
