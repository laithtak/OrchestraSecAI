"""Cooperative cancellation / ownership checks for a running scan."""

from __future__ import annotations

import time
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from orchestrasecai.persistence.tables.core import Scan, ScanStatus


class ScanStopped(Exception):
    """The scan is no longer running under this worker (cancelled, timed out, reassigned)."""


class ScanControl:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        scan_id: UUID,
        job_id: str,
        *,
        min_interval_seconds: float = 2.0,
    ) -> None:
        self._factory = session_factory
        self.scan_id = scan_id
        self.job_id = job_id
        self._min_interval = min_interval_seconds
        self._last_check = 0.0
        self._stopped = False

    async def is_stopped(self) -> bool:
        if self._stopped:
            return True
        now = time.monotonic()
        if now - self._last_check < self._min_interval:
            return False
        self._last_check = now
        async with self._factory() as db:
            r = await db.execute(
                select(Scan.status, Scan.worker_job_id).where(Scan.id == self.scan_id)
            )
            row = r.one_or_none()
        if row is None or row.status != ScanStatus.running or row.worker_job_id != self.job_id:
            self._stopped = True
        return self._stopped

    async def ensure_running(self) -> None:
        if await self.is_stopped():
            raise ScanStopped(str(self.scan_id))
