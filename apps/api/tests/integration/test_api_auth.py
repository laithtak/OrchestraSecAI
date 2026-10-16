"""Login works for the documented development seed identity (special-use .local domain)."""

import uuid

import pytest

from orchestrasecai.persistence.tables.core import Organization, User, UserRole
from orchestrasecai.security.auth import hash_password

pytestmark = pytest.mark.asyncio


async def test_login_accepts_local_domain_accounts(api, db_factory):
    client, _ = api
    email = f"admin-{uuid.uuid4().hex[:8]}@orchestrasec.local"
    async with db_factory() as db:
        org = Organization(name="Auth org", slug=f"auth-{uuid.uuid4().hex[:8]}")
        db.add(org)
        await db.flush()
        db.add(
            User(
                org_id=org.id,
                email=email,
                password_hash=hash_password("correct horse battery"),
                role=UserRole.owner,
                is_active=True,
            )
        )
        await db.commit()

    r = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": "correct horse battery"}
    )
    assert r.status_code == 200 and r.json()["access_token"]
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": "wrong"})
    assert r.status_code == 401
