from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.deps import require_perm
from orchestrasecai.api.schemas import TargetCreate, TargetOut, UserOut
from orchestrasecai.persistence.session import get_db
from orchestrasecai.domain.verification import (
    check_dns_txt_verification,
    target_hostname,
    verification_instructions,
)
from orchestrasecai.persistence.tables.core import Project, ScanTarget, VerificationStatus
from orchestrasecai.security.ssrf import SSRFError, validate_target_url

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=list[TargetOut])
async def list_targets(
    user: UserOut = Depends(require_perm("targets:read")),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(ScanTarget).where(ScanTarget.org_id == user.org_id))
    return [
        TargetOut(
            id=t.id,
            project_id=t.project_id,
            base_url=t.base_url,
            allowed_hosts=list(t.allowed_hosts or []),
            verification_status=t.verification_status.value,
        )
        for t in r.scalars().all()
    ]


@router.post("", response_model=TargetOut, status_code=201)
async def create_target(
    body: TargetCreate,
    user: UserOut = Depends(require_perm("targets:write")),
    db: AsyncSession = Depends(get_db),
):
    proj = await db.get(Project, body.project_id)
    if not proj or proj.org_id != user.org_id:
        raise HTTPException(404, "Project not found")
    try:
        validate_target_url(body.base_url)
    except SSRFError as e:
        raise HTTPException(400, str(e)) from e
    t = ScanTarget(
        org_id=user.org_id,
        project_id=body.project_id,
        base_url=body.base_url,
        allowed_hosts=body.allowed_hosts,
        verification_status=VerificationStatus.unverified,
    )
    db.add(t)
    await db.flush()
    return TargetOut(
        id=t.id,
        project_id=t.project_id,
        base_url=t.base_url,
        allowed_hosts=list(t.allowed_hosts or []),
        verification_status=t.verification_status.value,
    )


@router.get("/{target_id}/verification")
async def get_target_verification(
    target_id: UUID,
    user: UserOut = Depends(require_perm("targets:read")),
    db: AsyncSession = Depends(get_db),
):
    t = await db.get(ScanTarget, target_id)
    if not t or t.org_id != user.org_id:
        raise HTTPException(404, "Target not found")
    domain = target_hostname(t.base_url)
    if not domain:
        raise HTTPException(400, "Target has no valid hostname")
    instructions = verification_instructions(str(t.id), domain)
    return {
        **instructions,
        "verification_status": t.verification_status.value,
        "target_id": str(t.id),
    }


@router.post("/{target_id}/verify", response_model=TargetOut)
async def verify_target(
    target_id: UUID,
    user: UserOut = Depends(require_perm("targets:write")),
    db: AsyncSession = Depends(get_db),
):
    t = await db.get(ScanTarget, target_id)
    if not t or t.org_id != user.org_id:
        raise HTTPException(404, "Target not found")
    domain = target_hostname(t.base_url)
    if not domain:
        raise HTTPException(400, "Target has no valid hostname")
    if check_dns_txt_verification(domain, str(t.id)):
        t.verification_status = VerificationStatus.verified
    else:
        t.verification_status = VerificationStatus.pending
    await db.flush()
    return TargetOut(
        id=t.id,
        project_id=t.project_id,
        base_url=t.base_url,
        allowed_hosts=list(t.allowed_hosts or []),
        verification_status=t.verification_status.value,
    )
