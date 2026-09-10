import asyncio
import json
from uuid import UUID

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.deps import require_perm
from orchestrasecai.api.schemas import AgentSessionOut, FindingOut, ScanCreate, ScanOut, UserOut
from orchestrasecai.api.middleware.rate_limit import check_scan_daily_limit
from orchestrasecai.observability.context import bind_context
from orchestrasecai.observability.metrics import rate_limit_exceeded_total
from orchestrasecai.observability.tracing import enqueue_with_context
from orchestrasecai.domain.verification import can_scan_unverified_target
from orchestrasecai.config import get_settings
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import (
    AgentSession,
    CrawlPage,
    Finding,
    Scan,
    ScanPolicy,
    ScanStatus,
    ScanTarget,
    VerificationStatus,
)
from orchestrasecai.api.schemas import FindingOut
from orchestrasecai.observability.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])
_settings = get_settings()


async def _enqueue(scan_id: str, request_id: str | None = None) -> None:
    pool = await create_pool(RedisSettings.from_dsn(_settings.redis_url))
    await enqueue_with_context(
        pool,
        "run_agent_scan_task",
        scan_id,
        request_id=request_id,
    )
    await pool.aclose()


@router.get("", response_model=list[ScanOut])
async def list_scans(
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
    status: str | None = None,
):
    q = select(Scan).where(Scan.org_id == user.org_id).order_by(Scan.created_at.desc())
    if status:
        q = q.where(Scan.status == ScanStatus(status))
    r = await db.execute(q.limit(50))
    scans = r.scalars().all()
    return [_scan_out(s) for s in scans]


def _scan_out(s: Scan) -> ScanOut:
    return ScanOut(
        id=s.id,
        status=s.status.value,
        mission=s.mission,
        created_at=s.created_at,
        stats=s.stats or {},
        links={
            "self": f"/api/v1/scans/{s.id}",
            "events": f"/api/v1/scans/{s.id}/events",
            "agent_session": f"/api/v1/scans/{s.id}/agent-session",
        },
    )


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(
    body: ScanCreate,
    request: Request,
    user: UserOut = Depends(require_perm("scans:write")),
    db: AsyncSession = Depends(get_db),
):
    target = await db.get(ScanTarget, body.scan_target_id)
    policy = await db.get(ScanPolicy, body.scan_policy_id)
    if not target or target.org_id != user.org_id:
        raise HTTPException(404, "Target not found")
    if not policy or policy.org_id != user.org_id:
        raise HTTPException(404, "Policy not found")
    if target.verification_status != VerificationStatus.verified and not can_scan_unverified_target():
        raise HTTPException(403, "Target must be verified before scanning")

    redis: Redis | None = getattr(request.app.state, "redis", None)
    scripts = getattr(request.app.state, "rate_limit_scripts", None)
    if redis is not None:
        allowed, _remaining = await check_scan_daily_limit(redis, user.org_id, scripts)
        if not allowed:
            rate_limit_exceeded_total.labels(limiter="org_daily").inc()
            raise HTTPException(429, "Daily scan limit exceeded")

    if body.plugin_ids is not None:
        logger.warning("plugin_ids_deprecated", scan_target_id=str(body.scan_target_id))

    scan = Scan(
        org_id=user.org_id,
        scan_target_id=body.scan_target_id,
        scan_policy_id=body.scan_policy_id,
        mission=body.mission,
        plugin_ids=body.plugin_ids,
        status=ScanStatus.queued,
        created_by=user.id,
    )
    db.add(scan)
    await db.flush()

    agent_session = AgentSession(
        scan_id=scan.id,
        mission=body.mission,
        max_iterations=_settings.agent_max_iterations,
    )
    db.add(agent_session)
    await db.flush()
    bind_context(scan_id=str(scan.id), org_id=str(user.org_id))
    request.state.scan_id = scan.id
    request.state.audit_record = {
        "org_id": user.org_id,
        "user_id": user.id,
        "action": "scan.create",
        "resource_type": "scan",
        "resource_id": str(scan.id),
    }
    request_id = getattr(request.state, "request_id", None)
    await _enqueue(str(scan.id), request_id=request_id)
    return _scan_out(scan)


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: UUID,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")
    bind_context(scan_id=str(scan_id))
    return _scan_out(s)


@router.get("/{scan_id}/pages")
async def list_pages(
    scan_id: UUID,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")
    bind_context(scan_id=str(scan_id))
    r = await db.execute(select(CrawlPage).where(CrawlPage.scan_id == scan_id))
    pages = r.scalars().all()
    return [
        {
            "id": str(p.id),
            "url": p.url,
            "status_code": p.status_code,
            "depth": p.depth,
        }
        for p in pages
    ]


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def scan_findings(
    scan_id: UUID,
    severity: str | None = None,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")
    bind_context(scan_id=str(scan_id))
    q = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        from orchestrasecai.persistence.tables.core import Severity

        q = q.where(Finding.severity == Severity(severity))
    r = await db.execute(q)
    return [
        FindingOut(
            id=f.id,
            plugin_id=f.plugin_id,
            severity=f.severity.value,
            title=f.title,
            description=f.description,
            location=f.location,
            status=f.status.value,
        )
        for f in r.scalars().all()
    ]


@router.post("/{scan_id}/analyze")
async def reanalyze(
    scan_id: UUID,
    request: Request,
    user: UserOut = Depends(require_perm("scans:write")),
    db: AsyncSession = Depends(get_db),
):
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")
    bind_context(scan_id=str(scan_id), org_id=str(user.org_id))
    pool = await create_pool(RedisSettings.from_dsn(_settings.redis_url))
    request_id = getattr(request.state, "request_id", None)
    await enqueue_with_context(
        pool,
        "run_ai_analysis_task",
        str(scan_id),
        request_id=request_id,
    )
    await pool.aclose()
    return {"status": "queued"}


@router.get("/{scan_id}/agent-session", response_model=AgentSessionOut)
async def get_agent_session(
    scan_id: UUID,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")
    r = await db.execute(select(AgentSession).where(AgentSession.scan_id == scan_id))
    session = r.scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Agent session not found")
    bind_context(scan_id=str(scan_id))
    return AgentSessionOut(
        mission=session.mission,
        status=session.status.value,
        iteration=session.iteration,
        max_iterations=session.max_iterations,
        trace=session.trace or [],
        summary=session.summary or {},
    )


@router.get("/{scan_id}/events")
async def scan_events(
    scan_id: UUID,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")
    bind_context(scan_id=str(scan_id))

    async def event_stream():
        redis = Redis.from_url(_settings.redis_url)
        pubsub = redis.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}:events")
        try:
            yield f"event: connected\ndata: {json.dumps({'scan_id': str(scan_id)})}\n\n"
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=30.0)
                if msg and msg["type"] == "message":
                    data = msg["data"]
                    if isinstance(data, bytes):
                        data = data.decode()
                    yield f"event: message\ndata: {data}\n\n"
                else:
                    yield ": keepalive\n\n"
                await asyncio.sleep(0.1)
        finally:
            await pubsub.unsubscribe(f"scan:{scan_id}:events")
            await redis.aclose()

    return StreamingResponse(event_stream(), media_type="text/event-stream")
