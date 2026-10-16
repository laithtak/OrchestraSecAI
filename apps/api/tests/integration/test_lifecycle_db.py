"""Atomic lifecycle transitions, leases, the stale-scan reaper and finding dedup on Postgres."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from orchestrasecai.checks.base import FindingDraft
from orchestrasecai.domain.scan_lifecycle import claim_for_execution, heartbeat, transition
from orchestrasecai.domain.services.finding_store import persist_findings
from orchestrasecai.domain.services.reaper import reap_stale_scans
from orchestrasecai.persistence.tables.core import (
    Finding,
    FindingEvidence,
    Scan,
    ScanStatus,
    ScanTarget,
    VerificationStatus,
)

pytestmark = pytest.mark.asyncio
NOW = datetime.now(UTC)


async def make_scan(db_factory, tenant, **values) -> Scan:
    async with db_factory() as db:
        target = ScanTarget(
            org_id=tenant.org_id,
            project_id=tenant.project_id,
            base_url="https://app.example.com/",
            allowed_hosts=[],
            verification_status=VerificationStatus.unverified,
        )
        db.add(target)
        await db.flush()
        scan = Scan(
            org_id=tenant.org_id,
            scan_target_id=target.id,
            scan_policy_id=tenant.policy_id,
            mission="lifecycle test mission",
            status=ScanStatus.queued,
            attempts=0,
            **values,
        )
        db.add(scan)
        await db.commit()
        return scan


async def get(db_factory, scan_id) -> Scan:
    async with db_factory() as db:
        return await db.get(Scan, scan_id)


async def claim(db_factory, scan_id, job, now=NOW, max_attempts=2):
    async with db_factory() as db:
        ok = await claim_for_execution(
            db, scan_id, job_id=job, now=now, lease_seconds=60,
            max_attempts=max_attempts, timeout_seconds=600,
        )
        await db.commit()
        return ok


async def test_claim_is_exclusive_and_deadline_is_fixed(db_factory, tenant_a):
    scan = await make_scan(db_factory, tenant_a)
    assert await claim(db_factory, scan.id, "job-1") is True
    assert await claim(db_factory, scan.id, "job-2") is False  # duplicate delivery
    s = await get(db_factory, scan.id)
    assert (s.status, s.attempts, s.worker_job_id) == (ScanStatus.running, 1, "job-1")
    deadline = s.deadline_at

    # Lease expiry allows takeover by a new job, but never extends the deadline.
    later = NOW + timedelta(seconds=120)
    assert await claim(db_factory, scan.id, "job-2", now=later) is True
    s = await get(db_factory, scan.id)
    assert (s.attempts, s.worker_job_id, s.deadline_at) == (2, "job-2", deadline)
    # Max attempts reached.
    assert await claim(db_factory, scan.id, "job-3", now=later + timedelta(seconds=120)) is False


async def test_heartbeat_requires_ownership(db_factory, tenant_a):
    scan = await make_scan(db_factory, tenant_a)
    await claim(db_factory, scan.id, "job-1")
    async with db_factory() as db:
        assert await heartbeat(db, scan.id, job_id="job-1", now=NOW, lease_seconds=60)
        assert not await heartbeat(db, scan.id, job_id="intruder", now=NOW, lease_seconds=60)
        await db.commit()


async def test_terminal_states_are_final_and_races_resolve_once(db_factory, tenant_a):
    scan = await make_scan(db_factory, tenant_a)
    await claim(db_factory, scan.id, "job-1")
    async with db_factory() as db:
        assert await transition(db, scan.id, ScanStatus.cancelled)
        # The worker finishing afterwards must not overwrite the cancellation.
        assert not await transition(
            db, scan.id, ScanStatus.completed, from_states=[ScanStatus.running], worker_job_id="job-1"
        )
        assert not await transition(db, scan.id, ScanStatus.failed)
        assert not await heartbeat(db, scan.id, job_id="job-1", now=NOW, lease_seconds=60)
        await db.commit()
    assert (await get(db_factory, scan.id)).status == ScanStatus.cancelled


async def test_database_rejects_unknown_status(db_factory, tenant_a):
    scan = await make_scan(db_factory, tenant_a)
    async with db_factory() as db:
        from sqlalchemy import text

        with pytest.raises(IntegrityError):
            await db.execute(
                text("UPDATE scans SET status = 'agent_running' WHERE id = :id"), {"id": scan.id}
            )


async def test_reaper_recovers_stale_scans(db_factory, tenant_a):
    timed_out = await make_scan(db_factory, tenant_a)
    lost = await make_scan(db_factory, tenant_a)
    retry = await make_scan(db_factory, tenant_a)
    stale_queue = await make_scan(db_factory, tenant_a)
    ancient_queue = await make_scan(db_factory, tenant_a)
    healthy = await make_scan(db_factory, tenant_a)
    past = NOW - timedelta(seconds=1)
    async with db_factory() as db:
        for scan_id, values in [
            (timed_out.id, {"status": ScanStatus.running, "attempts": 1, "deadline_at": past,
                            "lease_expires_at": NOW + timedelta(minutes=1)}),
            (lost.id, {"status": ScanStatus.running, "attempts": 2, "lease_expires_at": past,
                       "deadline_at": NOW + timedelta(minutes=10)}),
            (retry.id, {"status": ScanStatus.running, "attempts": 1, "lease_expires_at": past,
                        "deadline_at": NOW + timedelta(minutes=10)}),
            (stale_queue.id, {"created_at": NOW - timedelta(minutes=5)}),
            (ancient_queue.id, {"created_at": NOW - timedelta(hours=2)}),
            (healthy.id, {"status": ScanStatus.running, "attempts": 1,
                          "lease_expires_at": NOW + timedelta(minutes=1),
                          "deadline_at": NOW + timedelta(minutes=10)}),
        ]:
            await db.execute(update(Scan).where(Scan.id == scan_id).values(**values))
        await db.commit()

    enqueued: list[tuple[str, str]] = []

    async def enqueue(scan_id, job_id):
        enqueued.append((scan_id, job_id))

    counts = await reap_stale_scans(enqueue=enqueue, session_factory=db_factory, now=NOW)
    assert counts["timed_out"] >= 1 and counts["worker_lost"] >= 1 and counts["queue_timeout"] >= 1

    assert (await get(db_factory, timed_out.id)).status == ScanStatus.timed_out
    s = await get(db_factory, lost.id)
    assert (s.status, s.error_code) == (ScanStatus.failed, "worker_lost")
    s = await get(db_factory, ancient_queue.id)
    assert (s.status, s.error_code) == (ScanStatus.failed, "queue_timeout")
    assert (await get(db_factory, healthy.id)).status == ScanStatus.running
    assert (str(retry.id), f"scan:{retry.id}:attempt:2") in enqueued
    assert (str(stale_queue.id), f"scan:{stale_queue.id}") in enqueued
    assert all(sid != str(healthy.id) for sid, _ in enqueued)


async def test_findings_are_deduplicated_and_redacted(db_factory, tenant_a):
    scan = await make_scan(db_factory, tenant_a)
    draft = FindingDraft(
        plugin_id="header.missing_content_security_policy",
        severity="medium",
        title="Missing Content-Security-Policy header",
        description="desc",
        fingerprint="a" * 32,
        location={"url": "https://app.example.com/"},
        evidence=[
            {
                "evidence_type": "http_response",
                "payload": {
                    "headers": {
                        "Set-Cookie": "sid=topsecret; HttpOnly",
                        "Authorization": "Bearer abcdefghijklmnop",
                        "Server": "nginx",
                    }
                },
            }
        ],
    )
    async with db_factory() as db:
        s = await db.get(Scan, scan.id)
        assert await persist_findings(db, s, [draft], set(), check_id="header") == 1
        # A retried attempt starts with an empty in-memory set: the DB still dedups.
        assert await persist_findings(db, s, [draft], set(), check_id="header") == 0
        await db.commit()
        rows = (await db.execute(select(Finding).where(Finding.scan_id == scan.id))).scalars().all()
        assert len(rows) == 1
        f = rows[0]
        assert f.check_id == "header" and "Content-Security-Policy" in f.remediation
        payload = (
            await db.execute(select(FindingEvidence.payload).where(FindingEvidence.finding_id == f.id))
        ).scalar_one()
        assert payload["headers"]["Set-Cookie"].startswith("sid=[REDACTED]")
        assert payload["headers"]["Authorization"] == "[REDACTED]"
        assert payload["headers"]["Server"] == "nginx"
        n = await db.scalar(select(func.count()).select_from(FindingEvidence).where(FindingEvidence.finding_id == f.id))
        assert n == 1
