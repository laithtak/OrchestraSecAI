from uuid import UUID

from fastapi import Depends, HTTPException, Request
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.schemas import UserOut
from orchestrasecai.observability.context import bind_context
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import User, UserRole
from orchestrasecai.security.auth import decode_token
from orchestrasecai.security.rbac import require_permission


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth[7:]
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = UUID(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token") from None

    result = await db.execute(select(User).where(User.id == user_id, User.is_active.is_(True)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    request.state.org_id = user.org_id
    bind_context(org_id=str(user.org_id))
    return UserOut(id=user.id, email=user.email, role=user.role.value, org_id=user.org_id)


def require_perm(permission: str):
    async def _checker(user: UserOut = Depends(get_current_user)) -> UserOut:
        require_permission(UserRole(user.role), permission)
        return user

    return _checker
