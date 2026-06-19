from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.deps import require_perm
from orchestrasecai.api.schemas import ProjectCreate, ProjectOut, UserOut
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import Project

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[ProjectOut])
async def list_projects(
    user: UserOut = Depends(require_perm("projects:read")),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(Project).where(Project.org_id == user.org_id))
    return list(r.scalars().all())


@router.post("", response_model=ProjectOut, status_code=201)
async def create_project(
    body: ProjectCreate,
    user: UserOut = Depends(require_perm("projects:write")),
    db: AsyncSession = Depends(get_db),
):
    p = Project(org_id=user.org_id, name=body.name, description=body.description)
    db.add(p)
    await db.flush()
    return p


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: UUID,
    user: UserOut = Depends(require_perm("projects:read")),
    db: AsyncSession = Depends(get_db),
):
    p = await db.get(Project, project_id)
    if not p or p.org_id != user.org_id:
        raise HTTPException(404, "Project not found")
    return p
