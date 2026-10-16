"""PostgreSQL-backed integration tests.

Run after ``alembic upgrade head`` against the database in DATABASE_URL (CI provisions
one). Tests are skipped when the database is unreachable. No test touches a real
third-party host: DNS and HTTP are always simulated in-process.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from orchestrasecai.config import get_settings
from orchestrasecai.persistence.tables.core import (
    Organization,
    Project,
    ScanPolicy,
    User,
    UserRole,
)
from orchestrasecai.security.auth import create_access_token

PUBLIC_IP = "93.184.216.34"


_DB_AVAILABLE: dict[str, bool] = {}


async def _db_available(url: str) -> bool:
    if url in _DB_AVAILABLE:
        return _DB_AVAILABLE[url]
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with asyncio.timeout(3):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1 FROM domain_verification_challenges LIMIT 1"))
        _DB_AVAILABLE[url] = True
    except Exception:  # noqa: BLE001 - any failure means "not provisioned"
        _DB_AVAILABLE[url] = False
    finally:
        await engine.dispose()
    return _DB_AVAILABLE[url]


@pytest_asyncio.fixture
async def db_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    url = get_settings().database_url
    if not await _db_available(url):
        pytest.skip("PostgreSQL with migrations applied is not available")
    engine = create_async_engine(url, poolclass=NullPool)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@dataclass
class Tenant:
    org_id: uuid.UUID
    project_id: uuid.UUID
    policy_id: uuid.UUID
    users: dict[str, uuid.UUID] = field(default_factory=dict)

    def headers(self, role: str = "owner") -> dict[str, str]:
        token = create_access_token(str(self.users[role]), str(self.org_id), role)
        return {"Authorization": f"Bearer {token}"}


async def make_tenant(factory: async_sessionmaker[AsyncSession]) -> Tenant:
    suffix = uuid.uuid4().hex[:10]
    async with factory() as db:
        org = Organization(name=f"Org {suffix}", slug=f"org-{suffix}")
        db.add(org)
        await db.flush()
        project = Project(org_id=org.id, name="Project")
        policy = ScanPolicy(
            org_id=org.id,
            name="Test policy",
            max_pages=5,
            max_depth=1,
            requests_per_second=50,
            respect_robots_txt=False,
            user_agent="OrchestraSecAI-Test",
        )
        db.add_all([project, policy])
        users = {}
        for role in ("owner", "analyst", "viewer"):
            user = User(
                org_id=org.id,
                email=f"{role}-{suffix}@example.test",
                password_hash="not-a-real-hash",
                role=UserRole(role),
                is_active=True,
            )
            db.add(user)
            await db.flush()
            users[role] = user.id
        await db.commit()
        return Tenant(org_id=org.id, project_id=project.id, policy_id=policy.id, users=users)


@pytest_asyncio.fixture
async def tenant_a(db_factory) -> Tenant:
    return await make_tenant(db_factory)


@pytest_asyncio.fixture
async def tenant_b(db_factory) -> Tenant:
    return await make_tenant(db_factory)


class FakeDns:
    """In-process DNS: A/AAAA answers for the egress layer and TXT records for verification."""

    def __init__(self) -> None:
        self.addresses: dict[str, list[str]] = {}
        self.txt: dict[str, list[str]] = {}
        self.txt_queries: list[str] = []

    async def resolve(self, host: str, port: int) -> list[str]:
        if host not in self.addresses:
            raise OSError("NXDOMAIN")
        return self.addresses[host]

    async def fetch_txt(self, name: str) -> list[str]:
        self.txt_queries.append(name)
        return list(self.txt.get(name, []))


@pytest.fixture
def fake_dns(monkeypatch) -> FakeDns:
    dns = FakeDns()
    # Every default-resolver call in the codebase goes through ssrf.system_resolver.
    monkeypatch.setattr("orchestrasecai.security.ssrf.system_resolver", dns.resolve)
    monkeypatch.setattr("orchestrasecai.domain.verification.fetch_txt_values", dns.fetch_txt)
    return dns


@dataclass
class QueueRecorder:
    jobs: list[str] = field(default_factory=list)
    fail: bool = False

    async def __call__(self, scan_id: str, request_id: str | None = None) -> None:
        if self.fail:
            raise ConnectionError("redis unavailable")
        self.jobs.append(scan_id)


@pytest_asyncio.fixture
async def api(db_factory, fake_dns, monkeypatch) -> AsyncIterator[tuple[httpx.AsyncClient, QueueRecorder]]:
    from orchestrasecai.api.v1 import scans as scans_module
    from orchestrasecai.main import app
    from orchestrasecai.persistence.session import get_db

    async def override_db():
        async with db_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    queue = QueueRecorder()
    monkeypatch.setattr("orchestrasecai.api.middleware.audit.async_session_factory", db_factory)
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[scans_module.get_enqueue] = lambda: queue
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client, queue
    app.dependency_overrides.clear()


async def create_verified_target(
    client: httpx.AsyncClient, tenant: Tenant, dns: FakeDns, host: str = "app.example.com"
) -> dict:
    dns.addresses[host] = [PUBLIC_IP]
    r = await client.post(
        "/api/v1/targets",
        json={"project_id": str(tenant.project_id), "base_url": f"https://{host}/"},
        headers=tenant.headers(),
    )
    assert r.status_code == 201, r.text
    target = r.json()
    r = await client.post(
        f"/api/v1/targets/{target['id']}/verification/challenge", headers=tenant.headers()
    )
    assert r.status_code == 200, r.text
    dns.txt[f"_orchestrasec.{host}"] = [r.json()["record_value"]]
    r = await client.post(f"/api/v1/targets/{target['id']}/verify", headers=tenant.headers())
    assert r.status_code == 200, r.text
    assert r.json()["verification_status"] == "verified"
    return target
