"""Scan creation, authorization gate, cancellation and tenant isolation via the API."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select, update

from orchestrasecai.config import get_settings
from orchestrasecai.persistence.tables.audit import AuditLog
from orchestrasecai.persistence.tables.core import Scan, ScanStatus, ScanTarget

from .conftest import PUBLIC_IP, create_verified_target

pytestmark = pytest.mark.asyncio
MISSION = "Assess security headers and cookie configuration of the app."


def scan_body(tenant, target_id, **extra):
    return {
        "scan_target_id": str(target_id),
        "scan_policy_id": str(tenant.policy_id),
        "mission": MISSION,
        **extra,
    }


async def test_unverified_target_cannot_be_scanned(api, tenant_a, fake_dns):
    client, queue = api
    fake_dns.addresses["app.example.com"] = [PUBLIC_IP]
    target = (
        await client.post(
            "/api/v1/targets",
            json={"project_id": str(tenant_a.project_id), "base_url": "https://app.example.com/"},
            headers=tenant_a.headers(),
        )
    ).json()
    r = await client.post(
        "/api/v1/scans", json=scan_body(tenant_a, target["id"]), headers=tenant_a.headers()
    )
    assert r.status_code == 403
    assert "target_unverified" in r.json()["detail"]
    assert queue.jobs == []


async def test_expired_verification_cannot_be_scanned(api, tenant_a, fake_dns, db_factory):
    client, queue = api
    target = await create_verified_target(client, tenant_a, fake_dns)
    async with db_factory() as db:
        await db.execute(
            update(ScanTarget)
            .where(ScanTarget.id == UUID(target["id"]))
            .values(verification_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db.commit()
    r = await client.post(
        "/api/v1/scans", json=scan_body(tenant_a, target["id"]), headers=tenant_a.headers()
    )
    assert r.status_code == 403
    assert "verification_expired" in r.json()["detail"]
    assert queue.jobs == []


async def test_verified_scan_is_created_committed_and_enqueued(api, tenant_a, fake_dns, db_factory):
    client, queue = api
    target = await create_verified_target(client, tenant_a, fake_dns)
    r = await client.post(
        "/api/v1/scans", json=scan_body(tenant_a, target["id"]), headers=tenant_a.headers("analyst")
    )
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "queued"
    assert scan["active_probes_enabled"] is False
    assert scan["target_id"] == target["id"]
    assert queue.jobs == [scan["id"]]
    async with db_factory() as db:  # visible to other connections (i.e. the worker)
        row = await db.get(Scan, UUID(scan["id"]))
        assert row.status == ScanStatus.queued


async def test_queue_failure_marks_scan_failed(api, tenant_a, fake_dns, db_factory):
    client, queue = api
    target = await create_verified_target(client, tenant_a, fake_dns)
    queue.fail = True
    r = await client.post(
        "/api/v1/scans", json=scan_body(tenant_a, target["id"]), headers=tenant_a.headers()
    )
    assert r.status_code == 503
    async with db_factory() as db:
        scans = (
            await db.execute(select(Scan).where(Scan.scan_target_id == UUID(target["id"])))
        ).scalars().all()
    assert [(s.status, s.error_code) for s in scans] == [(ScanStatus.failed, "queue_unavailable")]


async def test_active_probe_opt_in_requires_permission_and_deployment_flag(
    api, tenant_a, fake_dns, db_factory, monkeypatch
):
    client, queue = api
    target = await create_verified_target(client, tenant_a, fake_dns)
    body = scan_body(tenant_a, target["id"], allow_active_probes=True)

    r = await client.post("/api/v1/scans", json=body, headers=tenant_a.headers("analyst"))
    assert r.status_code == 403 and "scans:active" in r.json()["detail"]

    monkeypatch.setattr(get_settings(), "active_probes_allowed", False)
    r = await client.post("/api/v1/scans", json=body, headers=tenant_a.headers())
    assert r.status_code == 403 and "disabled" in r.json()["detail"]
    assert queue.jobs == []

    monkeypatch.setattr(get_settings(), "active_probes_allowed", True)
    r = await client.post("/api/v1/scans", json=body, headers=tenant_a.headers())
    assert r.status_code == 201
    assert r.json()["active_probes_enabled"] is True
    async with db_factory() as db:
        actions = set(
            (
                await db.execute(
                    select(AuditLog.action).where(AuditLog.resource_id == r.json()["id"])
                )
            ).scalars()
        )
    assert {"scan.create", "scan.active_probes_opt_in"} <= actions


async def test_cancel_lifecycle(api, tenant_a, tenant_b, fake_dns):
    client, _ = api
    target = await create_verified_target(client, tenant_a, fake_dns)
    scan = (
        await client.post(
            "/api/v1/scans", json=scan_body(tenant_a, target["id"]), headers=tenant_a.headers()
        )
    ).json()
    path = f"/api/v1/scans/{scan['id']}/cancel"

    assert (await client.post(path, headers=tenant_b.headers())).status_code == 404
    assert (await client.post(path, headers=tenant_a.headers("viewer"))).status_code == 403

    r = await client.post(path, headers=tenant_a.headers("analyst"))
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"
    assert r.json()["error_code"] == "cancelled"
    assert r.json()["finished_at"] is not None

    r = await client.post(path, headers=tenant_a.headers())
    assert r.status_code == 409


async def test_scan_resources_are_tenant_isolated(api, tenant_a, tenant_b, fake_dns):
    client, _ = api
    target = await create_verified_target(client, tenant_a, fake_dns)
    scan = (
        await client.post(
            "/api/v1/scans", json=scan_body(tenant_a, target["id"]), headers=tenant_a.headers()
        )
    ).json()
    for path in [
        f"/api/v1/scans/{scan['id']}",
        f"/api/v1/scans/{scan['id']}/findings",
        f"/api/v1/scans/{scan['id']}/pages",
        f"/api/v1/scans/{scan['id']}/agent-session",
        f"/api/v1/scans/{scan['id']}/report?format=json",
    ]:
        r = await client.get(path, headers=tenant_b.headers())
        assert r.status_code == 404, path
    r = await client.get("/api/v1/scans", headers=tenant_b.headers())
    assert r.json() == []

    # Tenant B cannot start a scan against tenant A's target or with A's policy.
    r = await client.post(
        "/api/v1/scans",
        json={
            "scan_target_id": target["id"],
            "scan_policy_id": str(tenant_b.policy_id),
            "mission": MISSION,
        },
        headers=tenant_b.headers(),
    )
    assert r.status_code == 404


async def test_invalid_filters_are_rejected(api, tenant_a, fake_dns):
    client, _ = api
    assert (
        await client.get("/api/v1/scans?status=agent_running", headers=tenant_a.headers())
    ).status_code == 400
    target = await create_verified_target(client, tenant_a, fake_dns)
    scan = (
        await client.post(
            "/api/v1/scans", json=scan_body(tenant_a, target["id"]), headers=tenant_a.headers()
        )
    ).json()
    r = await client.get(
        f"/api/v1/scans/{scan['id']}/findings?severity=critical", headers=tenant_a.headers()
    )
    assert r.status_code == 400
    r = await client.get(f"/api/v1/scans/{scan['id']}/report?format=pdf", headers=tenant_a.headers())
    assert r.status_code == 400
