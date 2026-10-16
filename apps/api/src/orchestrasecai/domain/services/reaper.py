"""Stale-scan reaper: recovers from worker crashes, lost jobs and missed deadlines.

Runs periodically (ARQ cron). Every action is a compare-and-set transition, so the
reaper can race with workers and the API without producing contradictory states.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from orchestrasecai.config import get_settings
from orchestrasecai.domain.scan_lifecycle import ScanErrorCode, transition
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.observability.metrics import scan_outcomes_total, scan_reaper_actions_total
from orchestrasecai.persistence.tables.core import Scan, ScanStatus

logger = get_logger(__name__)
BATCH_LIMIT = 100

Enqueue = Callable[[str, str], Awaitable[None]]


async def reap_stale_scans(
    *,
    enqueue: Enqueue,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    settings = get_settings()
    now = now or datetime.now(UTC)
    counts = {"timed_out": 0, "worker_lost": 0, "requeued": 0, "queue_timeout": 0}

    engine = None
    factory = session_factory
    if factory is None:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with factory() as db:
            running = (
                await db.execute(
                    select(Scan.id, Scan.attempts, Scan.deadline_at, Scan.lease_expires_at)
                    .where(Scan.status == ScanStatus.running)
                    .limit(BATCH_LIMIT)
                )
            ).all()
            queued = (
                await db.execute(
                    select(Scan.id, Scan.created_at)
                    .where(Scan.status == ScanStatus.queued)
                    .order_by(Scan.created_at)
                    .limit(BATCH_LIMIT)
                )
            ).all()

        for row in running:
            terminal: tuple[ScanStatus, ScanErrorCode, str] | None = None
            if row.deadline_at is not None and row.deadline_at <= now:
                terminal = (ScanStatus.timed_out, ScanErrorCode.timeout, "timed_out")
            elif row.lease_expires_at is None or row.lease_expires_at < now:
                if row.attempts >= settings.scan_max_attempts:
                    terminal = (ScanStatus.failed, ScanErrorCode.worker_lost, "worker_lost")
                else:
                    await enqueue(str(row.id), f"scan:{row.id}:attempt:{row.attempts + 1}")
                    counts["requeued"] += 1
                    scan_reaper_actions_total.labels(action="requeue_after_lease").inc()
            if terminal is not None:
                status, code, key = terminal
                async with factory() as db:
                    changed = await transition(
                        db,
                        row.id,
                        status,
                        from_states=[ScanStatus.running],
                        error_code=code,
                        values={"finished_at": now},
                    )
                    await db.commit()
                if changed:
                    counts[key] += 1
                    scan_reaper_actions_total.labels(action=key).inc()
                    scan_outcomes_total.labels(status=status.value).inc()
                    await publish_event(
                        str(row.id),
                        "scan.status_changed",
                        {"status": status.value, "error_code": code.value},
                    )

        max_age = timedelta(seconds=settings.scan_queue_max_age_seconds)
        requeue_after = timedelta(seconds=settings.scan_requeue_after_seconds)
        for row in queued:
            age = now - row.created_at
            if age > max_age:
                async with factory() as db:
                    changed = await transition(
                        db,
                        row.id,
                        ScanStatus.failed,
                        from_states=[ScanStatus.queued],
                        error_code=ScanErrorCode.queue_timeout,
                        values={"finished_at": now},
                    )
                    await db.commit()
                if changed:
                    counts["queue_timeout"] += 1
                    scan_reaper_actions_total.labels(action="queue_timeout").inc()
                    scan_outcomes_total.labels(status=ScanStatus.failed.value).inc()
            elif age > requeue_after:
                # Same job id as the original enqueue: ARQ ignores it while that job still
                # exists, so this only re-creates jobs lost from Redis.
                await enqueue(str(row.id), f"scan:{row.id}")
                counts["requeued"] += 1
                scan_reaper_actions_total.labels(action="requeue_queued").inc()
    finally:
        if engine is not None:
            await engine.dispose()
    return counts
