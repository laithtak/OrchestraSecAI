from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.deps import require_perm
from orchestrasecai.api.schemas import FindingOut, FindingPatch, UserOut
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import Finding, FindingStatus

router = APIRouter(prefix="/findings", tags=["findings"])


@router.patch("/{finding_id}", response_model=FindingOut)
async def patch_finding(
    finding_id: UUID,
    body: FindingPatch,
    user: UserOut = Depends(require_perm("findings:write")),
    db: AsyncSession = Depends(get_db),
):
    f = await db.get(Finding, finding_id)
    if not f or f.org_id != user.org_id:
        raise HTTPException(404, "Finding not found")
    try:
        f.status = FindingStatus(body.status)
    except ValueError:
        raise HTTPException(400, "Invalid status") from None
    await db.flush()
    return FindingOut(
        id=f.id,
        plugin_id=f.plugin_id,
        severity=f.severity.value,
        title=f.title,
        description=f.description,
        location=f.location,
        status=f.status.value,
    )
