"""Agent-driven scan execution with a durable, idempotent lifecycle.

1. Atomically claim the scan (queued -> running, or lease takeover after a crash).
   A duplicate or replayed job fails the claim and exits without side effects.
2. Re-authorize at execution time: tenant bindings, verified + unexpired ownership of the
   exact target hostname, canonical scope, and public DNS resolution.
3. Run the LangGraph agent under supervision: a heartbeat task extends the lease and
   stops execution when the scan is cancelled or reassigned; a deadline fixed at first
   claim bounds total time across retries.
4. Atomically complete (running -> completed) and store the deterministic report in the
   same transaction. AI enrichment is enqueued afterwards and is optional.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
from arq import create_pool
from arq.connections import RedisSettings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from orchestrasecai.agent.graph import build_agent_graph
from orchestrasecai.agent.llm import AgentLLM
from orchestrasecai.agent.state import AgentState
from orchestrasecai.config import get_settings
from orchestrasecai.domain.reporting import store_report
from orchestrasecai.domain.scan_lifecycle import (
    ScanErrorCode,
    claim_for_execution,
    heartbeat,
    transition,
)
from orchestrasecai.domain.services.audit import write_audit_log
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.domain.services.scan_control import ScanControl, ScanStopped
from orchestrasecai.domain.verification import AuthorizationDenied, authorize_target_for_scan
from orchestrasecai.observability.context import bind_context
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.observability.metrics import scan_duration_seconds, scan_outcomes_total
from orchestrasecai.observability.tracing import enqueue_with_context
from orchestrasecai.persistence.tables.core import (
    AgentSession,
    AgentSessionStatus,
    Finding,
    Scan,
    ScanPolicy,
    ScanStatus,
    ScanTarget,
)
from orchestrasecai.scanner.tools.layer import ScanToolLayer
from orchestrasecai.security.scope import DEFAULT_PORTS, ScopeError, target_scope
from orchestrasecai.security.ssrf import Resolver, SSRFError, resolve_public_addresses

logger = get_logger(__name__)
TRACE_CAP = 500

_DENIAL_CODES = {
    AuthorizationDenied.unverified: ScanErrorCode.target_unverified,
    AuthorizationDenied.expired: ScanErrorCode.verification_expired,
    AuthorizationDenied.domain_mismatch: ScanErrorCode.verification_domain_mismatch,
    AuthorizationDenied.invalid_target: ScanErrorCode.invalid_target,
}


@dataclass
class RunnerDeps:
    """Injectable collaborators (tests substitute DNS, HTTP and the queue)."""

    session_factory: async_sessionmaker[AsyncSession] | None = None
    resolver: Resolver | None = None
    transport: httpx.AsyncBaseTransport | None = None
    llm: AgentLLM | None = None
    enqueue_ai: Callable[[str, str | None], Awaitable[None]] | None = None


def _now() -> datetime:
    return datetime.now(UTC)


async def _enqueue_ai_analysis(scan_id: str, request_id: str | None) -> None:
    settings = get_settings()
    pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await enqueue_with_context(
            pool,
            "run_ai_analysis_task",
            scan_id,
            request_id=request_id,
            _job_id=f"ai:{scan_id}",
        )
    finally:
        await pool.aclose()


async def _flush_trace(session: AgentSession, new_entries: list[dict]) -> None:
    trace = list(session.trace or [])
    trace.extend(new_entries)
    if len(trace) > TRACE_CAP:
        session.summary = {
            **(session.summary or {}),
            "truncated_entries": len(trace) - TRACE_CAP,
        }
        trace = trace[-TRACE_CAP:]
    session.trace = trace
    session.updated_at = _now()


async def authorize_execution(
    db: AsyncSession, scan: Scan, *, now: datetime, resolver: Resolver | None = None
) -> ScanErrorCode | None:
    """Re-establish authorization from persisted state; never trust the job payload."""
    target = await db.get(ScanTarget, scan.scan_target_id)
    policy = await db.get(ScanPolicy, scan.scan_policy_id)
    if (
        target is None
        or policy is None
        or target.org_id != scan.org_id
        or policy.org_id != scan.org_id
    ):
        return ScanErrorCode.invalid_target
    denial = authorize_target_for_scan(target, org_id=scan.org_id, now=now)
    if denial is not None:
        return _DENIAL_CODES[denial]
    try:
        scope = target_scope(target.base_url, list(target.allowed_hosts or []))
    except ScopeError:
        return ScanErrorCode.invalid_target
    scheme = scope.base_url.split(":", 1)[0]
    try:
        await resolve_public_addresses(scope.hostname, DEFAULT_PORTS[scheme], resolver)
    except SSRFError:
        return ScanErrorCode.target_unreachable
    return None


async def _fail(
    factory: async_sessionmaker[AsyncSession],
    scan_id: UUID,
    job_id: str,
    code: ScanErrorCode,
    to: ScanStatus = ScanStatus.failed,
) -> bool:
    async with factory() as db:
        changed = await transition(
            db,
            scan_id,
            to,
            from_states=[ScanStatus.running],
            error_code=code,
            worker_job_id=job_id,
            values={"finished_at": _now()},
        )
        r = await db.execute(select(AgentSession).where(AgentSession.scan_id == scan_id))
        session = r.scalar_one_or_none()
        if changed and session is not None and session.status == AgentSessionStatus.running:
            session.status = AgentSessionStatus.failed
        await db.commit()
    if changed:
        scan_outcomes_total.labels(status=to.value).inc()
        await publish_event(
            str(scan_id), "scan.status_changed", {"status": to.value, "error_code": code.value}
        )
    return changed


async def _execute_agent(
    factory: async_sessionmaker[AsyncSession],
    scan_id: UUID,
    job_id: str,
    deps: RunnerDeps,
) -> None:
    settings = get_settings()
    async with factory() as db:
        scan = await db.get(Scan, scan_id)
        target = await db.get(ScanTarget, scan.scan_target_id)
        policy = await db.get(ScanPolicy, scan.scan_policy_id)

        r = await db.execute(select(AgentSession).where(AgentSession.scan_id == scan.id))
        agent_session = r.scalar_one_or_none()
        if not agent_session:
            agent_session = AgentSession(
                scan_id=scan.id,
                mission=scan.mission,
                max_iterations=settings.agent_max_iterations,
            )
            db.add(agent_session)
            await db.flush()
        agent_session.status = AgentSessionStatus.running

        # Retries resume with existing findings so persistence stays idempotent.
        fr = await db.execute(select(Finding.fingerprint).where(Finding.scan_id == scan.id))
        seen = set(fr.scalars().all())
        await db.commit()

        # Active probes need the deployment flag, the scan's audited opt-in, and must not
        # be repeated by a crash-recovery attempt.
        allow_active = bool(
            scan.active_probes_enabled and settings.active_probes_allowed and scan.attempts == 1
        )
        tool_layer = ScanToolLayer(
            db=db,
            scan=scan,
            target=target,
            policy=policy,
            seen_fingerprints=seen,
            user_id=scan.created_by,
            control=ScanControl(factory, scan.id, job_id),
            allow_active=allow_active,
            resolver=deps.resolver,
            transport=deps.transport,
        )
        await publish_event(str(scan_id), "scan.status_changed", {"status": "running"})

        graph = build_agent_graph(tool_layer, llm=deps.llm)
        initial_state: AgentState = {
            "scan_id": str(scan_id),
            "session_id": str(agent_session.id),
            "mission": scan.mission,
            "target_url": target.base_url,
            "policy": {
                "max_pages": policy.max_pages,
                "max_depth": policy.max_depth,
                "requests_per_second": float(policy.requests_per_second),
            },
            "findings_summary": [],
            "iteration": 0,
            "max_iterations": min(agent_session.max_iterations, settings.agent_max_iterations),
            "trace_entries": [],
            "follow_up_hints": [],
            "complete": False,
        }
        final_state = await graph.ainvoke(initial_state)

        await _flush_trace(agent_session, final_state.get("trace_entries", []))
        agent_session.iteration = final_state.get("iteration", agent_session.iteration)
        critique = final_state.get("critique")
        agent_session.summary = {
            **(agent_session.summary or {}),
            "findings_count": len(final_state.get("findings_summary", [])),
            "termination_reason": final_state.get("termination_reason"),
            "last_critique": critique.model_dump() if critique else None,
        }
        agent_session.status = (
            AgentSessionStatus.max_iterations
            if final_state.get("termination_reason") == "max_iterations"
            else AgentSessionStatus.complete
        )
        fr = await db.execute(select(Finding.id).where(Finding.scan_id == scan.id))
        scan.stats = {
            **(scan.stats or {}),
            "findings_count": len(fr.scalars().all()),
            "agent_iterations": final_state.get("iteration", 0),
            "requests_used": tool_layer.budget.used,
        }
        await db.commit()


async def _finalize(
    factory: async_sessionmaker[AsyncSession],
    scan_id: UUID,
    job_id: str,
    to: ScanStatus,
    error_code: ScanErrorCode | None = None,
) -> bool:
    """Atomic terminal transition plus the deterministic report, in one transaction."""
    async with factory() as db:
        changed = await transition(
            db,
            scan_id,
            to,
            from_states=[ScanStatus.running],
            error_code=error_code,
            worker_job_id=job_id,
            values={"finished_at": _now()},
        )
        if not changed:
            await db.rollback()
            return False
        scan = await db.get(Scan, scan_id)
        await db.refresh(scan)
        await store_report(db, scan)
        await write_audit_log(
            db,
            org_id=scan.org_id,
            user_id=None,
            action=f"scan.{to.value}",
            resource_type="scan",
            resource_id=str(scan_id),
            metadata={"job_id": job_id, "findings": (scan.stats or {}).get("findings_count", 0)},
        )
        await db.commit()
    scan_outcomes_total.labels(status=to.value).inc()
    await publish_event(str(scan_id), "scan.status_changed", {"status": to.value})
    return True


async def run_agent_scan(
    scan_id: str,
    request_id: str | None = None,
    *,
    job_id: str | None = None,
    deps: RunnerDeps | None = None,
) -> str:
    """Execute a scan job. Returns the outcome; never raises for scan-level failures."""
    settings = get_settings()
    deps = deps or RunnerDeps()
    bind_context(scan_id=scan_id, request_id=request_id)
    try:
        scan_uuid = UUID(str(scan_id))
    except ValueError:
        logger.warning("scan_job_invalid_payload")
        return "invalid_payload"
    job_id = job_id or f"adhoc:{uuid4()}"

    engine = None
    factory = deps.session_factory
    if factory is None:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        factory = async_sessionmaker(engine, expire_on_commit=False)

    started = time.perf_counter()
    try:
        async with factory() as db:
            claimed = await claim_for_execution(
                db,
                scan_uuid,
                job_id=job_id,
                now=_now(),
                lease_seconds=settings.scan_lease_seconds,
                max_attempts=settings.scan_max_attempts,
                timeout_seconds=settings.scan_global_timeout_seconds,
            )
            await db.commit()
        if not claimed:
            logger.info("scan_claim_skipped", scan_id=scan_id, job_id=job_id)
            return "skipped"

        async with factory() as db:
            scan = await db.get(Scan, scan_uuid)
            bind_context(org_id=str(scan.org_id))
            denial = await authorize_execution(db, scan, now=_now(), resolver=deps.resolver)
            if denial is not None:
                await write_audit_log(
                    db,
                    org_id=scan.org_id,
                    user_id=None,
                    action="scan.execution_denied",
                    resource_type="scan",
                    resource_id=str(scan.id),
                    metadata={"reason": denial.value, "job_id": job_id},
                )
                await db.commit()
                logger.warning("scan_execution_denied", scan_id=scan_id, reason=denial.value)
                await _fail(factory, scan_uuid, job_id, denial)
                return ScanStatus.failed.value
            deadline = scan.deadline_at

        outcome = await _supervise(factory, scan_uuid, job_id, deadline, deps)
        if outcome == ScanStatus.completed.value:
            try:
                await (deps.enqueue_ai or _enqueue_ai_analysis)(scan_id, request_id)
            except Exception as exc:  # noqa: BLE001 - AI enrichment is optional
                logger.warning("ai_enrichment_enqueue_failed", error_type=type(exc).__name__)
        return outcome
    finally:
        scan_duration_seconds.labels(phase="total").observe(time.perf_counter() - started)
        if engine is not None:
            await engine.dispose()


async def _supervise(
    factory: async_sessionmaker[AsyncSession],
    scan_id: UUID,
    job_id: str,
    deadline: datetime,
    deps: RunnerDeps,
) -> str:
    settings = get_settings()
    stopped = asyncio.Event()
    main = asyncio.create_task(_execute_agent(factory, scan_id, job_id, deps))

    async def watch() -> None:
        while not main.done():
            await asyncio.sleep(settings.scan_heartbeat_seconds)
            try:
                async with factory() as db:
                    owned = await heartbeat(
                        db,
                        scan_id,
                        job_id=job_id,
                        now=_now(),
                        lease_seconds=settings.scan_lease_seconds,
                    )
                    await db.commit()
            except Exception as exc:  # noqa: BLE001 - keep running; the lease decides
                logger.warning("scan_heartbeat_failed", error_type=type(exc).__name__)
                continue
            if not owned:
                stopped.set()
                main.cancel()
                return

    watcher = asyncio.create_task(watch())
    remaining = max((deadline - _now()).total_seconds(), 1.0)
    try:
        async with asyncio.timeout(remaining):
            await main
    except TimeoutError:
        logger.warning("scan_timed_out", scan_id=str(scan_id))
        if await _finalize(factory, scan_id, job_id, ScanStatus.timed_out, ScanErrorCode.timeout):
            return ScanStatus.timed_out.value
        return await _status(factory, scan_id)
    except (ScanStopped, asyncio.CancelledError):
        current = asyncio.current_task()
        if current is not None and current.cancelling():
            raise  # the job itself is being cancelled (worker shutdown): propagate
        logger.info("scan_stopped", scan_id=str(scan_id), lost_lease=stopped.is_set())
        return await _status(factory, scan_id)
    except Exception as exc:  # noqa: BLE001 - convert to a persisted, sanitized failure
        logger.error("agent_scan_failed", scan_id=str(scan_id), error_type=type(exc).__name__)
        await _fail(factory, scan_id, job_id, ScanErrorCode.internal_error)
        return ScanStatus.failed.value
    finally:
        watcher.cancel()

    try:
        if await _finalize(factory, scan_id, job_id, ScanStatus.completed):
            logger.info("agent_scan_completed", scan_id=str(scan_id))
            return ScanStatus.completed.value
    except Exception as exc:  # noqa: BLE001
        logger.error("scan_finalize_failed", scan_id=str(scan_id), error_type=type(exc).__name__)
        await _fail(factory, scan_id, job_id, ScanErrorCode.internal_error)
        return ScanStatus.failed.value
    return await _status(factory, scan_id)


async def _status(factory: async_sessionmaker[AsyncSession], scan_id: UUID) -> str:
    async with factory() as db:
        r = await db.execute(select(Scan.status).where(Scan.id == scan_id))
        status: Any = r.scalar_one_or_none()
    return getattr(status, "value", str(status))
