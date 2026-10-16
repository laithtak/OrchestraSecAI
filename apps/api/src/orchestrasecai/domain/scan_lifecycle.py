"""Durable scan lifecycle: legal transitions, atomic claims, leases and heartbeats.

Every status change is a single conditional ``UPDATE ... WHERE status IN (...)``
(compare-and-set) so concurrent actors — API cancellation, the executing worker, a
duplicate job, the stale-scan reaper — cannot produce contradictory transitions.

    queued  -> running | failed | cancelled
    running -> completed | failed | cancelled | timed_out
    running -> running   (lease takeover after a worker crash, bounded by max attempts)

completed, failed, cancelled and timed_out are terminal.
"""

from __future__ import annotations

import enum
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.persistence.tables.core import Scan, ScanStatus

TERMINAL_STATES = frozenset(
    {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled, ScanStatus.timed_out}
)
ACTIVE_STATES = frozenset({ScanStatus.queued, ScanStatus.running})

ALLOWED_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.queued: frozenset({ScanStatus.running, ScanStatus.failed, ScanStatus.cancelled}),
    ScanStatus.running: frozenset(
        {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled, ScanStatus.timed_out}
    ),
}


class ScanErrorCode(str, enum.Enum):
    """Stable, non-sensitive failure reasons exposed to API clients."""

    target_unverified = "target_unverified"
    verification_expired = "verification_expired"
    verification_domain_mismatch = "verification_domain_mismatch"
    invalid_target = "invalid_target"
    target_unreachable = "target_unreachable"
    queue_unavailable = "queue_unavailable"
    queue_timeout = "queue_timeout"
    worker_lost = "worker_lost"
    timeout = "timeout"
    cancelled = "cancelled"
    internal_error = "internal_error"


ERROR_MESSAGES: dict[ScanErrorCode, str] = {
    ScanErrorCode.target_unverified: "Target ownership is not verified.",
    ScanErrorCode.verification_expired: "Target ownership verification has expired.",
    ScanErrorCode.verification_domain_mismatch: (
        "Verified domain does not match the target hostname."
    ),
    ScanErrorCode.invalid_target: "Target, policy or organization binding is invalid.",
    ScanErrorCode.target_unreachable: (
        "Target hostname could not be resolved to an allowed public address."
    ),
    ScanErrorCode.queue_unavailable: "The job queue was unavailable; the scan was not started.",
    ScanErrorCode.queue_timeout: "The scan was not picked up by a worker in time.",
    ScanErrorCode.worker_lost: "The worker executing the scan stopped responding.",
    ScanErrorCode.timeout: "The scan exceeded its execution time budget.",
    ScanErrorCode.cancelled: "The scan was cancelled.",
    ScanErrorCode.internal_error: "The scan failed due to an internal error.",
}


class IllegalTransition(ValueError):
    pass


def assert_transition(src: ScanStatus, dst: ScanStatus) -> None:
    if dst not in ALLOWED_TRANSITIONS.get(src, frozenset()):
        raise IllegalTransition(f"Illegal scan transition {src.value} -> {dst.value}")


def sources_for(dst: ScanStatus) -> list[ScanStatus]:
    return [src for src, targets in ALLOWED_TRANSITIONS.items() if dst in targets]


async def transition(
    db: AsyncSession,
    scan_id: UUID,
    to: ScanStatus,
    *,
    from_states: list[ScanStatus] | None = None,
    error_code: ScanErrorCode | None = None,
    worker_job_id: str | None = None,
    values: dict | None = None,
) -> bool:
    """Atomically move a scan to ``to``. Returns False if the scan was not in a source state."""
    sources = from_states or sources_for(to)
    for src in sources:
        assert_transition(src, to)
    conditions = [Scan.id == scan_id, Scan.status.in_(sources)]
    if worker_job_id is not None:
        conditions.append(Scan.worker_job_id == worker_job_id)
    new_values: dict = {"status": to, **(values or {})}
    if to in TERMINAL_STATES:
        new_values.setdefault("lease_expires_at", None)
    if error_code is not None:
        new_values["error_code"] = error_code.value
        new_values["error_message"] = ERROR_MESSAGES[error_code]
    result = await db.execute(
        update(Scan)
        .where(*conditions)
        .values(**new_values)
        .returning(Scan.id)
        .execution_options(synchronize_session=False)
    )
    return result.scalar_one_or_none() is not None


async def claim_for_execution(
    db: AsyncSession,
    scan_id: UUID,
    *,
    job_id: str,
    now: datetime,
    lease_seconds: int,
    max_attempts: int,
    timeout_seconds: int,
) -> bool:
    """Claim a queued scan, or take over a running scan whose lease expired.

    The deadline is fixed on the first claim, so recovery attempts never extend the
    total execution budget.
    """
    lease = now + timedelta(seconds=lease_seconds)
    result = await db.execute(
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.attempts < max_attempts,
            or_(
                Scan.status == ScanStatus.queued,
                and_(
                    Scan.status == ScanStatus.running,
                    Scan.lease_expires_at.is_not(None),
                    Scan.lease_expires_at < now,
                ),
            ),
            or_(Scan.deadline_at.is_(None), Scan.deadline_at > now),
        )
        .values(
            status=ScanStatus.running,
            attempts=Scan.attempts + 1,
            lease_expires_at=lease,
            worker_job_id=job_id,
            started_at=func.coalesce(Scan.started_at, now),
            deadline_at=func.coalesce(
                Scan.deadline_at, now + timedelta(seconds=timeout_seconds)
            ),
        )
        .returning(Scan.id)
        .execution_options(synchronize_session=False)
    )
    return result.scalar_one_or_none() is not None


async def heartbeat(
    db: AsyncSession, scan_id: UUID, *, job_id: str, now: datetime, lease_seconds: int
) -> bool:
    """Extend the lease. False means this worker no longer owns a running scan."""
    result = await db.execute(
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.status == ScanStatus.running,
            Scan.worker_job_id == job_id,
        )
        .values(lease_expires_at=now + timedelta(seconds=lease_seconds))
        .returning(Scan.id)
        .execution_options(synchronize_session=False)
    )
    return result.scalar_one_or_none() is not None


async def current_status(db: AsyncSession, scan_id: UUID) -> ScanStatus | None:
    r = await db.execute(select(Scan.status).where(Scan.id == scan_id))
    return r.scalar_one_or_none()
