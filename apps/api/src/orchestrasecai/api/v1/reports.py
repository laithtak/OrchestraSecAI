from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.deps import get_current_user, require_perm
from orchestrasecai.api.schemas import UserOut
from orchestrasecai.api.services.report_tokens import consume_report_view_token, create_report_view_token
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import Report, ReportFormat, Scan, UserRole
from orchestrasecai.security.rbac import require_permission

router = APIRouter(tags=["reports"])


async def _fetch_report_content(db: AsyncSession, scan_id: UUID, fmt: ReportFormat) -> Report:
    r = await db.execute(
        select(Report)
        .where(Report.scan_id == scan_id, Report.format == fmt)
        .order_by(Report.version.desc())
        .limit(1)
    )
    report = r.scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not ready")
    return report


def _report_response(report: Report, fmt: ReportFormat) -> Response:
    if fmt == ReportFormat.html:
        return Response(content=report.content, media_type="text/html")
    return Response(content=report.content, media_type="application/json")


@router.post("/scans/{scan_id}/report/view-token")
async def create_report_view_token_endpoint(
    scan_id: UUID,
    request: Request,
    format: str = "html",
    user: UserOut = Depends(require_perm("reports:read")),
    db: AsyncSession = Depends(get_db),
):
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")

    redis: Redis | None = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(503, "Report view tokens unavailable")

    fmt = "html" if format == "html" else "json"
    token = await create_report_view_token(redis, scan_id, user.org_id, user.id, fmt)
    return {
        "url": f"/api/v1/scans/{scan_id}/report?format={fmt}&token={token}",
    }


@router.get("/scans/{scan_id}/report")
async def get_report(
    scan_id: UUID,
    request: Request,
    format: str = "html",
    token: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    fmt = ReportFormat.html if format == "html" else ReportFormat.json

    if token:
        redis: Redis | None = getattr(request.app.state, "redis", None)
        if redis is None:
            raise HTTPException(503, "Report view tokens unavailable")
        payload = await consume_report_view_token(redis, token)
        if not payload:
            raise HTTPException(401, "Invalid or expired report token")
        if UUID(payload["scan_id"]) != scan_id:
            raise HTTPException(401, "Invalid report token")
        if payload.get("format") != format:
            raise HTTPException(401, "Invalid report token")
        s = await db.get(Scan, scan_id)
        if not s or str(s.org_id) != payload["org_id"]:
            raise HTTPException(404, "Scan not found")
        report = await _fetch_report_content(db, scan_id, fmt)
        return _report_response(report, fmt)

    user = await get_current_user(request, db)
    require_permission(UserRole(user.role), "reports:read")
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")
    report = await _fetch_report_content(db, scan_id, fmt)
    return _report_response(report, fmt)
