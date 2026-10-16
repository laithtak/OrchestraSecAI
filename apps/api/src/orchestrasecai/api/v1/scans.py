import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from orchestrasecai.api.deps import require_perm
from orchestrasecai.api.middleware.rate_limit import check_scan_daily_limit
from orchestrasecai.api.schemas import (
    AgentSessionOut,
    EvidenceOut,
    FindingOut,
    ScanCreate,
    ScanOut,
    UserOut,
)
from orchestrasecai.config import get_settings
from orchestrasecai.domain.scan_lifecycle import (
    TERMINAL_STATES,
    ScanErrorCode,
    transition,
)
from orchestrasecai.domain.services.audit import write_audit_log
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.domain.verification import authorize_target_for_scan
from orchestrasecai.observability.context import bind_context
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.observability.metrics import rate_limit_exceeded_total
from orchestrasecai.observability.tracing import enqueue_with_context
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import (
    AgentSession,
    CrawlPage,
    Finding,
    Scan,
    ScanPolicy,
    ScanStatus,
    ScanTarget,
    Severity,
    UserRole,
)
from orchestrasecai.security.rbac import has_permission

logger = get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])
_settings = get_settings()


async def _enqueue(scan_id: str, request_id: str | None = None) -> None:
    pool = await create_pool(RedisSettings.from_dsn(_settings.redis_url))
    try:
        await enqueue_with_context(
            pool,
            "run_agent_scan_task",
            scan_id,
            request_id=request_id,
            _job_id=f"scan:{scan_id}",
        )
    finally:
        await pool.aclose()


def get_enqueue():
    """Dependency seam for the job queue (tests substitute it)."""
    return _enqueue


def _scan_out(s: Scan) -> ScanOut:
    return ScanOut(
        id=s.id,
        status=s.status.value,
        mission=s.mission,
        created_at=s.created_at,
        stats=s.stats or {},
        target_id=s.scan_target_id,
        started_at=s.started_at,
        finished_at=s.finished_at,
        error_code=s.error_code,
        error_message=s.error_message,
        attempts=s.attempts or 0,
        active_probes_enabled=bool(s.active_probes_enabled),
        links={
            "self": f"/api/v1/scans/{s.id}",
            "events": f"/api/v1/scans/{s.id}/events",
            "agent_session": f"/api/v1/scans/{s.id}/agent-session",
            "findings": f"/api/v1/scans/{s.id}/findings",
            "report": f"/api/v1/scans/{s.id}/report",
            "cancel": f"/api/v1/scans/{s.id}/cancel",
        },
    )


async def _get_owned_scan(db: AsyncSession, scan_id: UUID, user: UserOut) -> Scan:
    s = await db.get(Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "Scan not found")
    bind_context(scan_id=str(scan_id))
    return s


@router.get("", response_model=list[ScanOut])
async def list_scans(
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
    status: str | None = None,
):
    q = select(Scan).where(Scan.org_id == user.org_id).order_by(Scan.created_at.desc())
    if status:
        try:
            q = q.where(Scan.status == ScanStatus(status))
        except ValueError:
            raise HTTPException(400, "Invalid status filter") from None
    r = await db.execute(q.limit(50))
    return [_scan_out(s) for s in r.scalars().all()]


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(
    body: ScanCreate,
    request: Request,
    user: UserOut = Depends(require_perm("scans:write")),
    db: AsyncSession = Depends(get_db),
    enqueue=Depends(get_enqueue),
):
    target = await db.get(ScanTarget, body.scan_target_id)
    policy = await db.get(ScanPolicy, body.scan_policy_id)
    if not target or target.org_id != user.org_id:
        raise HTTPException(404, "Target not found")
    if not policy or policy.org_id != user.org_id:
        raise HTTPException(404, "Policy not found")
    denial = authorize_target_for_scan(target, org_id=user.org_id, now=datetime.now(UTC))
    if denial is not None:
        raise HTTPException(403, f"Target is not authorized for scanning: {denial.value}")
    if body.allow_active_probes:
        if not has_permission(UserRole(user.role), "scans:active"):
            raise HTTPException(403, "Permission denied: scans:active")
        if not _settings.active_probes_allowed:
            raise HTTPException(403, "Active probes are disabled on this deployment")

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
        scan_target_id=target.id,
        scan_policy_id=policy.id,
        mission=body.mission,
        plugin_ids=body.plugin_ids,
        status=ScanStatus.queued,
        created_by=user.id,
        active_probes_enabled=body.allow_active_probes,
        attempts=0,
    )
    db.add(scan)
    await db.flush()
    db.add(
        AgentSession(
            scan_id=scan.id,
            mission=body.mission,
            max_iterations=_settings.agent_max_iterations,
        )
    )
    await write_audit_log(
        db,
        org_id=user.org_id,
        user_id=user.id,
        action="scan.create",
        resource_type="scan",
        resource_id=str(scan.id),
        metadata={
            "target_id": str(target.id),
            "verified_domain": target.verified_domain,
            "active_probes_enabled": body.allow_active_probes,
        },
    )
    if body.allow_active_probes:
        await write_audit_log(
            db,
            org_id=user.org_id,
            user_id=user.id,
            action="scan.active_probes_opt_in",
            resource_type="scan",
            resource_id=str(scan.id),
            metadata={"target_id": str(target.id), "role": user.role},
        )
    # Commit before enqueueing so the worker can never observe a missing scan row.
    await db.commit()
    bind_context(scan_id=str(scan.id), org_id=str(user.org_id))
    request.state.scan_id = scan.id

    try:
        await enqueue(str(scan.id), getattr(request.state, "request_id", None))
    except Exception as exc:
        logger.error("scan_enqueue_failed", scan_id=str(scan.id), error_type=type(exc).__name__)
        await transition(
            db,
            scan.id,
            ScanStatus.failed,
            from_states=[ScanStatus.queued],
            error_code=ScanErrorCode.queue_unavailable,
            values={"finished_at": datetime.now(UTC)},
        )
        await db.commit()
        raise HTTPException(503, "Scan queue unavailable; the scan was not started") from exc
    await db.refresh(scan)
    return _scan_out(scan)


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: UUID,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    return _scan_out(await _get_owned_scan(db, scan_id, user))


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(
    scan_id: UUID,
    user: UserOut = Depends(require_perm("scans:write")),
    db: AsyncSession = Depends(get_db),
):
    s = await _get_owned_scan(db, scan_id, user)
    now = datetime.now(UTC)
    changed = await transition(
        db,
        s.id,
        ScanStatus.cancelled,
        from_states=[ScanStatus.queued, ScanStatus.running],
        error_code=ScanErrorCode.cancelled,
        values={"finished_at": now, "cancel_requested_at": now},
    )
    if not changed:
        await db.refresh(s)
        raise HTTPException(409, f"Scan is already {s.status.value}")
    await write_audit_log(
        db,
        org_id=user.org_id,
        user_id=user.id,
        action="scan.cancel",
        resource_type="scan",
        resource_id=str(s.id),
    )
    await db.commit()
    await db.refresh(s)
    await publish_event(str(s.id), "scan.status_changed", {"status": "cancelled"})
    return _scan_out(s)


@router.get("/{scan_id}/pages")
async def list_pages(
    scan_id: UUID,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    await _get_owned_scan(db, scan_id, user)
    r = await db.execute(select(CrawlPage).where(CrawlPage.scan_id == scan_id).limit(1000))
    return [
        {"id": str(p.id), "url": p.url, "status_code": p.status_code, "depth": p.depth}
        for p in r.scalars().all()
    ]


def _finding_out(f: Finding, *, with_evidence: bool) -> FindingOut:
    return FindingOut(
        id=f.id,
        scan_id=f.scan_id,
        plugin_id=f.plugin_id,
        severity=f.severity.value,
        title=f.title,
        description=f.description,
        location=f.location or {},
        status=f.status.value,
        fingerprint=f.fingerprint,
        remediation=f.remediation,
        check_id=f.check_id,
        check_version=f.check_version,
        created_at=f.created_at,
        evidence=[EvidenceOut(type=e.evidence_type, payload=e.payload) for e in f.evidence]
        if with_evidence
        else [],
    )


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def scan_findings(
    scan_id: UUID,
    severity: str | None = None,
    include_evidence: bool = False,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    await _get_owned_scan(db, scan_id, user)
    q = (
        select(Finding)
        .where(Finding.scan_id == scan_id, Finding.org_id == user.org_id)
        .order_by(Finding.created_at, Finding.fingerprint)
    )
    if include_evidence:
        q = q.options(selectinload(Finding.evidence))
    if severity:
        try:
            q = q.where(Finding.severity == Severity(severity))
        except ValueError:
            raise HTTPException(400, "Invalid severity filter") from None
    r = await db.execute(q)
    return [_finding_out(f, with_evidence=include_evidence) for f in r.scalars().all()]


@router.post("/{scan_id}/analyze")
async def reanalyze(
    scan_id: UUID,
    request: Request,
    user: UserOut = Depends(require_perm("scans:write")),
    db: AsyncSession = Depends(get_db),
):
    s = await _get_owned_scan(db, scan_id, user)
    if s.status not in (ScanStatus.completed, ScanStatus.timed_out):
        raise HTTPException(409, "AI analysis is only available for finished scans")
    bind_context(scan_id=str(scan_id), org_id=str(user.org_id))
    pool = await create_pool(RedisSettings.from_dsn(_settings.redis_url))
    try:
        await enqueue_with_context(
            pool,
            "run_ai_analysis_task",
            str(scan_id),
            request_id=getattr(request.state, "request_id", None),
        )
    finally:
        await pool.aclose()
    return {"status": "queued"}


@router.get("/{scan_id}/agent-session", response_model=AgentSessionOut)
async def get_agent_session(
    scan_id: UUID,
    user: UserOut = Depends(require_perm("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    await _get_owned_scan(db, scan_id, user)
    r = await db.execute(select(AgentSession).where(AgentSession.scan_id == scan_id))
    session = r.scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Agent session not found")
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
    s = await _get_owned_scan(db, scan_id, user)
    snapshot = {"event": "scan.snapshot", "status": s.status.value}
    terminal_values = {st.value for st in TERMINAL_STATES}

    async def event_stream():
        yield f"event: connected\ndata: {json.dumps({'scan_id': str(scan_id)})}\n\n"
        yield f"event: message\ndata: {json.dumps(snapshot)}\n\n"
        if snapshot["status"] in terminal_values:
            return
        redis = Redis.from_url(_settings.redis_url)
        pubsub = redis.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}:events")
        try:
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=30.0)
                if msg and msg["type"] == "message":
                    data = msg["data"]
                    if isinstance(data, bytes):
                        data = data.decode()
                    yield f"event: message\ndata: {data}\n\n"
                    try:
                        if json.loads(data).get("status") in terminal_values:
                            return
                    except (ValueError, AttributeError):
                        pass
                else:
                    yield ": keepalive\n\n"
                await asyncio.sleep(0.1)
        finally:
            await pubsub.unsubscribe(f"scan:{scan_id}:events")
            await redis.aclose()

    return StreamingResponse(event_stream(), media_type="text/event-stream")
