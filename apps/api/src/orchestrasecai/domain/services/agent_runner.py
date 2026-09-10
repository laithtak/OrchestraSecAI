"""Agent-driven scan runner — replaces linear crawl→plugins pipeline."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from uuid import UUID

from arq import create_pool
from arq.connections import RedisSettings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from orchestrasecai.agent.graph import build_agent_graph
from orchestrasecai.agent.state import AgentState
from orchestrasecai.config import get_settings
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.observability.context import bind_context
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.observability.metrics import scan_duration_seconds
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

settings = get_settings()
logger = get_logger(__name__)
TRACE_CAP = 500


async def _flush_trace(db: AsyncSession, session: AgentSession, new_entries: list[dict]) -> None:
    trace = list(session.trace or [])
    trace.extend(new_entries)
    if len(trace) > TRACE_CAP:
        session.summary = {
            **(session.summary or {}),
            "truncated_entries": len(trace) - TRACE_CAP,
        }
        trace = trace[-TRACE_CAP:]
    session.trace = trace
    session.updated_at = datetime.now(UTC)
    await db.commit()


async def run_agent_scan(scan_id: str, request_id: str | None = None) -> None:
    bind_context(scan_id=scan_id, request_id=request_id)
    scan_start = time.perf_counter()
    logger.info("agent_scan_started", scan_id=scan_id)

    engine_db = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine_db, expire_on_commit=False)
    seen_fps: set[str] = set()

    try:
        async with session_factory() as db:
            scan = await db.get(Scan, UUID(scan_id))
            if not scan:
                logger.warning("scan_not_found", scan_id=scan_id)
                return

            bind_context(org_id=str(scan.org_id))
            target = await db.get(ScanTarget, scan.scan_target_id)
            policy = await db.get(ScanPolicy, scan.scan_policy_id)
            if not target or not policy:
                scan.status = ScanStatus.failed
                scan.error_message = "Missing target or policy"
                await db.commit()
                return

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

            scan.status = ScanStatus.agent_running
            scan.started_at = scan.started_at or datetime.now(UTC)
            await db.commit()
            await publish_event(scan_id, "scan.status_changed", {"status": "agent_running"})

            tool_layer = ScanToolLayer(
                db=db,
                scan=scan,
                target=target,
                policy=policy,
                seen_fingerprints=seen_fps,
                user_id=scan.created_by,
            )

            graph = build_agent_graph(tool_layer)
            initial_state: AgentState = {
                "scan_id": scan_id,
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
                "max_iterations": agent_session.max_iterations,
                "trace_entries": [],
                "follow_up_hints": [],
                "complete": False,
            }

            final_state = await graph.ainvoke(initial_state)

            await _flush_trace(db, agent_session, final_state.get("trace_entries", []))
            agent_session.iteration = final_state.get("iteration", agent_session.iteration)
            agent_session.summary = {
                "findings_count": len(final_state.get("findings_summary", [])),
                "termination_reason": final_state.get("termination_reason"),
                "last_critique": (
                    final_state["critique"].model_dump()
                    if final_state.get("critique")
                    else None
                ),
            }

            if final_state.get("termination_reason") == "max_iterations":
                agent_session.status = AgentSessionStatus.max_iterations
            else:
                agent_session.status = AgentSessionStatus.complete

            fr = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
            findings_count = len(fr.scalars().all())
            scan.stats = {
                **(scan.stats or {}),
                "findings_count": findings_count,
                "agent_iterations": final_state.get("iteration", 0),
            }
            scan.status = ScanStatus.analyzing
            await db.commit()
            await publish_event(scan_id, "scan.status_changed", {"status": "analyzing"})

            pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
            await enqueue_with_context(
                pool,
                "run_ai_analysis_task",
                scan_id,
                request_id=request_id,
            )
            await pool.aclose()

        scan_duration_seconds.labels(phase="total").observe(time.perf_counter() - scan_start)
        logger.info("agent_scan_completed", scan_id=scan_id)
    except Exception as exc:
        logger.error("agent_scan_failed", scan_id=scan_id, error=str(exc))
        async with session_factory() as db:
            scan = await db.get(Scan, UUID(scan_id))
            if scan:
                scan.status = ScanStatus.failed
                scan.error_message = str(exc)
                r = await db.execute(select(AgentSession).where(AgentSession.scan_id == scan.id))
                sess = r.scalar_one_or_none()
                if sess:
                    sess.status = AgentSessionStatus.failed
                await db.commit()
        raise
    finally:
        await engine_db.dispose()
