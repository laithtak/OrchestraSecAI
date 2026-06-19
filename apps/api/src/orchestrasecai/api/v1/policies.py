from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.deps import require_perm
from orchestrasecai.api.schemas import PolicyCreate, PolicyOut, UserOut
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import ScanPolicy

router = APIRouter(prefix="/scan-policies", tags=["policies"])


@router.get("", response_model=list[PolicyOut])
async def list_policies(
    user: UserOut = Depends(require_perm("policies:read")),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(ScanPolicy).where(ScanPolicy.org_id == user.org_id))
    return list(r.scalars().all())


@router.post("", response_model=PolicyOut, status_code=201)
async def create_policy(
    body: PolicyCreate,
    user: UserOut = Depends(require_perm("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    p = ScanPolicy(
        org_id=user.org_id,
        name=body.name,
        max_pages=body.max_pages,
        max_depth=body.max_depth,
        requests_per_second=body.requests_per_second,
        respect_robots_txt=body.respect_robots_txt,
        user_agent=body.user_agent or "OrchestraSecAI-Scanner/0.1",
        blocked_path_patterns=body.blocked_path_patterns,
    )
    db.add(p)
    await db.flush()
    return p


@router.get("/{policy_id}", response_model=PolicyOut)
async def get_policy(
    policy_id: UUID,
    user: UserOut = Depends(require_perm("policies:read")),
    db: AsyncSession = Depends(get_db),
):
    p = await db.get(ScanPolicy, policy_id)
    if not p or p.org_id != user.org_id:
        raise HTTPException(404, "Policy not found")
    return p
