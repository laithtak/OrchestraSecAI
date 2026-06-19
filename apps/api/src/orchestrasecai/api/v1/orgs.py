"""Organizations API — multi-tenant switcher behind feature flag (Phase 4 stub)."""



from fastapi import APIRouter, Depends, HTTPException, status



from orchestrasecai.api.deps import get_current_user

from orchestrasecai.api.schemas import UserOut

from orchestrasecai.config import get_settings



router = APIRouter(prefix="/orgs", tags=["orgs"])

settings = get_settings()





@router.get("/current")

async def current_org(user: UserOut = Depends(get_current_user)) -> dict:

    return {

        "org_id": str(user.org_id),

        "multi_tenant_enabled": settings.multi_tenant_enabled,

    }





@router.get("")

async def list_orgs(user: UserOut = Depends(get_current_user)) -> list:

    if not settings.multi_tenant_enabled:

        raise HTTPException(

            status_code=status.HTTP_404_NOT_FOUND,

            detail="Multi-tenant org switcher disabled (MULTI_TENANT_ENABLED=false)",

        )

    return []


