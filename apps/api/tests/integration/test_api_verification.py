"""Target registration and DNS ownership verification through the HTTP API."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select, update

from orchestrasecai.persistence.tables.audit import AuditLog
from orchestrasecai.persistence.tables.core import DomainVerificationChallenge, ScanTarget

from .conftest import PUBLIC_IP, create_verified_target

pytestmark = pytest.mark.asyncio


async def _create_target(client, tenant, dns, host="app.example.com", **extra):
    dns.addresses.setdefault(host.lower(), [PUBLIC_IP])
    body = {"project_id": str(tenant.project_id), "base_url": f"https://{host}/", **extra}
    return await client.post("/api/v1/targets", json=body, headers=tenant.headers())


async def test_full_verification_flow_shows_token_once(api, tenant_a, fake_dns, db_factory):
    client, _ = api
    r = await _create_target(client, tenant_a, fake_dns, host="App.Example.com")
    assert r.status_code == 201
    target = r.json()
    assert target["base_url"] == "https://app.example.com/"
    assert target["verification_status"] == "unverified"
    assert target["scannable"] is False

    r = await client.get(f"/api/v1/targets/{target['id']}/verification", headers=tenant_a.headers())
    assert r.json()["record_name"] == "_orchestrasec.app.example.com"
    assert r.json()["record_value"] is None

    r = await client.post(
        f"/api/v1/targets/{target['id']}/verification/challenge", headers=tenant_a.headers()
    )
    issued = r.json()
    assert issued["verification_status"] == "pending"
    assert issued["record_value"].startswith("orchestrasec-verify=")
    token = issued["record_value"].split("=", 1)[1]

    # The plaintext token is never returned again and never stored.
    r = await client.get(f"/api/v1/targets/{target['id']}/verification", headers=tenant_a.headers())
    assert r.json()["record_value"] is None
    assert r.json()["token_hint"] == token[:6]
    async with db_factory() as db:
        ch = (
            await db.execute(
                select(DomainVerificationChallenge).where(
                    DomainVerificationChallenge.target_id == UUID(target["id"])
                )
            )
        ).scalar_one()
        assert token not in (ch.token_hash, ch.token_hint) and len(ch.token_hash) == 64

    r = await client.post(f"/api/v1/targets/{target['id']}/verify", headers=tenant_a.headers())
    assert r.status_code == 200
    assert r.json()["check_result"] == "record_not_found"
    assert r.json()["verification_status"] == "pending"

    fake_dns.txt["_orchestrasec.app.example.com"] = [issued["record_value"]]
    async with db_factory() as db:  # skip the anti-abuse cooldown
        await db.execute(
            update(DomainVerificationChallenge)
            .where(DomainVerificationChallenge.target_id == UUID(target["id"]))
            .values(last_checked_at=None)
        )
        await db.commit()
    r = await client.post(f"/api/v1/targets/{target['id']}/verify", headers=tenant_a.headers())
    body = r.json()
    assert body["check_result"] == "verified"
    assert body["verification_status"] == "verified"
    assert body["verified_domain"] == "app.example.com"
    assert fake_dns.txt_queries == ["_orchestrasec.app.example.com"] * 2

    r = await client.get(f"/api/v1/targets/{target['id']}", headers=tenant_a.headers())
    assert r.json()["scannable"] is True

    async with db_factory() as db:
        actions = set(
            (
                await db.execute(
                    select(AuditLog.action).where(AuditLog.resource_id == target["id"])
                )
            ).scalars()
        )
    assert {"target.verification_challenge_issued", "target.verification_check"} <= actions


async def test_rapid_rechecks_are_rate_limited(api, tenant_a, fake_dns):
    client, _ = api
    target = (await _create_target(client, tenant_a, fake_dns)).json()
    await client.post(
        f"/api/v1/targets/{target['id']}/verification/challenge", headers=tenant_a.headers()
    )
    assert (
        await client.post(f"/api/v1/targets/{target['id']}/verify", headers=tenant_a.headers())
    ).status_code == 200
    r = await client.post(f"/api/v1/targets/{target['id']}/verify", headers=tenant_a.headers())
    assert r.status_code == 429
    assert fake_dns.txt_queries == ["_orchestrasec.app.example.com"]


async def test_verify_without_challenge_conflicts(api, tenant_a, fake_dns):
    client, _ = api
    target = (await _create_target(client, tenant_a, fake_dns)).json()
    r = await client.post(f"/api/v1/targets/{target['id']}/verify", headers=tenant_a.headers())
    assert r.status_code == 409


async def test_rotation_invalidates_previous_token(api, tenant_a, fake_dns, db_factory):
    client, _ = api
    target = await create_verified_target(client, tenant_a, fake_dns)
    old_value = fake_dns.txt["_orchestrasec.app.example.com"][0]

    r = await client.post(
        f"/api/v1/targets/{target['id']}/verification/challenge", headers=tenant_a.headers()
    )
    assert r.json()["verification_status"] == "pending"
    assert r.json()["record_value"] != old_value

    r = await client.post(f"/api/v1/targets/{target['id']}/verify", headers=tenant_a.headers())
    assert r.json()["check_result"] == "token_mismatch"  # DNS still has the old token
    assert r.json()["verification_status"] == "pending"


async def test_expired_challenge_is_rejected(api, tenant_a, fake_dns, db_factory):
    client, _ = api
    target = (await _create_target(client, tenant_a, fake_dns)).json()
    r = await client.post(
        f"/api/v1/targets/{target['id']}/verification/challenge", headers=tenant_a.headers()
    )
    fake_dns.txt["_orchestrasec.app.example.com"] = [r.json()["record_value"]]
    async with db_factory() as db:
        await db.execute(
            update(DomainVerificationChallenge)
            .where(DomainVerificationChallenge.target_id == UUID(target["id"]))
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        await db.commit()
    r = await client.post(f"/api/v1/targets/{target['id']}/verify", headers=tenant_a.headers())
    assert r.json()["check_result"] == "challenge_expired"
    assert r.json()["verification_status"] == "unverified"


async def test_tenant_isolation_for_verification(api, tenant_a, tenant_b, fake_dns, db_factory):
    client, _ = api
    target_a = await create_verified_target(client, tenant_a, fake_dns)
    a_value = fake_dns.txt["_orchestrasec.app.example.com"][0]

    # Tenant B cannot see or act on tenant A's target.
    for method, path in [
        ("get", f"/api/v1/targets/{target_a['id']}"),
        ("get", f"/api/v1/targets/{target_a['id']}/verification"),
        ("post", f"/api/v1/targets/{target_a['id']}/verification/challenge"),
        ("post", f"/api/v1/targets/{target_a['id']}/verify"),
    ]:
        r = await getattr(client, method)(path, headers=tenant_b.headers())
        assert r.status_code == 404, path

    # Tenant B registers the same domain; A's published proof does not verify B.
    r = await _create_target(client, tenant_b, fake_dns)
    target_b = r.json()
    assert target_b["verification_status"] == "unverified"
    await client.post(
        f"/api/v1/targets/{target_b['id']}/verification/challenge", headers=tenant_b.headers()
    )
    assert fake_dns.txt["_orchestrasec.app.example.com"] == [a_value]
    r = await client.post(f"/api/v1/targets/{target_b['id']}/verify", headers=tenant_b.headers())
    assert r.json()["check_result"] == "token_mismatch"
    assert r.json()["verification_status"] == "pending"

    # A remains verified and B's state never leaks into A.
    r = await client.get(f"/api/v1/targets/{target_a['id']}", headers=tenant_a.headers())
    assert r.json()["verification_status"] == "verified"
    r = await client.get("/api/v1/targets", headers=tenant_b.headers())
    assert [t["id"] for t in r.json()] == [target_b["id"]]


async def test_rbac_and_authentication(api, tenant_a, fake_dns):
    client, _ = api
    target = (await _create_target(client, tenant_a, fake_dns)).json()
    path = f"/api/v1/targets/{target['id']}/verification/challenge"
    assert (await client.post(path)).status_code == 401
    assert (await client.post(path, headers=tenant_a.headers("analyst"))).status_code == 403
    assert (await client.post(path, headers=tenant_a.headers("viewer"))).status_code == 403
    r = await client.post(
        f"/api/v1/targets/{target['id']}/verify", headers=tenant_a.headers("viewer")
    )
    assert r.status_code == 403


async def test_request_cannot_self_assert_verification(api, tenant_a, fake_dns, db_factory):
    client, _ = api
    r = await _create_target(
        client,
        tenant_a,
        fake_dns,
        verification_status="verified",
        verified_domain="app.example.com",
    )
    assert r.status_code == 201
    assert r.json()["verification_status"] == "unverified"
    async with db_factory() as db:
        t = await db.get(ScanTarget, UUID(r.json()["id"]))
        assert t.verified_domain is None


@pytest.mark.parametrize(
    ("base_url", "allowed_hosts", "addresses"),
    [
        ("https://internal.example.com/", [], ["10.0.0.5"]),
        ("https://meta.example.com/", [], ["169.254.169.254"]),
        ("https://93.184.216.34/", [], None),
        ("http://localhost:8080/", [], None),
        ("https://app.example.com/", ["evil.example.net"], [PUBLIC_IP]),
        ("ftp://app.example.com/", [], [PUBLIC_IP]),
        ("https://nxdomain.example.com/", [], None),
    ],
)
async def test_unsafe_targets_are_rejected(
    api, tenant_a, fake_dns, base_url, allowed_hosts, addresses
):
    client, _ = api
    if addresses:
        from urllib.parse import urlsplit

        fake_dns.addresses[urlsplit(base_url).hostname] = addresses
    r = await client.post(
        "/api/v1/targets",
        json={
            "project_id": str(tenant_a.project_id),
            "base_url": base_url,
            "allowed_hosts": allowed_hosts,
        },
        headers=tenant_a.headers(),
    )
    assert r.status_code == 400, r.text


async def test_cross_tenant_project_is_rejected(api, tenant_a, tenant_b, fake_dns):
    client, _ = api
    fake_dns.addresses["app.example.com"] = [PUBLIC_IP]
    r = await client.post(
        "/api/v1/targets",
        json={"project_id": str(tenant_b.project_id), "base_url": "https://app.example.com/"},
        headers=tenant_a.headers(),
    )
    assert r.status_code == 404
