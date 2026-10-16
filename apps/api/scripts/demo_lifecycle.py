"""Executable local demo of the secure scan lifecycle against a mock target.

Drives the real FastAPI routes and the real worker execution path against PostgreSQL,
but replaces DNS and the target web server with in-process fakes, so no traffic leaves
the machine and no third-party system is scanned.

    cd apps/api
    alembic upgrade head
    python scripts/demo_lifecycle.py

Requires DATABASE_URL (migrated) and, optionally, REDIS_URL for live events. Data is
created in the seeded development organization, so the results are visible in the web
UI when logged in as SEED_ADMIN_EMAIL.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx
from sqlalchemy import select

from orchestrasecai.config import get_settings
from orchestrasecai.domain.services.agent_runner import RunnerDeps, run_agent_scan
from orchestrasecai.persistence.seed import run_seed
from orchestrasecai.persistence.session import async_session_factory
from orchestrasecai.persistence.tables.core import Project, ScanPolicy, User
from orchestrasecai.security.auth import create_access_token

DEMO_HOST = "shop.demo-target.test"
UNVERIFIED_HOST = "unverified.demo-target.test"
OUTPUT = Path("demo-output")

DNS_A: dict[str, list[str]] = {
    DEMO_HOST: ["93.184.216.34"],
    UNVERIFIED_HOST: ["93.184.216.34"],
}
DNS_TXT: dict[str, list[str]] = {}


async def fake_resolve(host: str, port: int) -> list[str]:
    if host not in DNS_A:
        raise OSError("NXDOMAIN")
    return DNS_A[host]


async def fake_txt(name: str) -> list[str]:
    return DNS_TXT.get(name, [])


def target_site(request: httpx.Request) -> httpx.Response:
    """A deliberately misconfigured shop: no security headers, weak cookie, CORS *."""
    if request.url.path in ("/", "/login", "/products"):
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "session=demo-session-secret; Path=/",
                "access-control-allow-origin": "*",
                "server": "nginx/1.18.0",
            },
            text='<html><a href="/login">Login</a> <a href="/products">Products</a></html>',
        )
    return httpx.Response(404, text="not found")


def step(title: str) -> None:
    print(f"\n=== {title}")


async def main() -> int:
    settings = get_settings()
    # Patch DNS for the API process (target creation + verification).
    from orchestrasecai.domain import verification
    from orchestrasecai.security import ssrf

    ssrf.system_resolver = fake_resolve  # type: ignore[assignment]
    verification.fetch_txt_values = fake_txt  # type: ignore[assignment]

    from orchestrasecai.api.v1 import scans as scans_api
    from orchestrasecai.main import app

    queued: list[str] = []

    async def record_enqueue(scan_id: str, request_id: str | None = None) -> None:
        queued.append(scan_id)

    app.dependency_overrides[scans_api.get_enqueue] = lambda: record_enqueue

    await run_seed()
    async with async_session_factory() as db:
        user = (
            await db.execute(select(User).where(User.email == settings.seed_admin_email))
        ).scalar_one_or_none()
        if user is None:
            print("Seed admin user not found; enable SEED_ENABLED on a fresh database.")
            return 1
        project = (
            await db.execute(select(Project).where(Project.org_id == user.org_id))
        ).scalars().first()
        policy = (
            await db.execute(select(ScanPolicy).where(ScanPolicy.org_id == user.org_id))
        ).scalars().first()
    headers = {
        "Authorization": "Bearer "
        + create_access_token(str(user.id), str(user.org_id), user.role.value)
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://demo") as api:
        step("1. Register a target")
        r = await api.post(
            "/api/v1/targets",
            json={"project_id": str(project.id), "base_url": f"https://{DEMO_HOST}/"},
            headers=headers,
        )
        r.raise_for_status()
        target = r.json()
        print(f"target {target['id']} {target['base_url']} -> {target['verification_status']}")

        step("2. Scanning before ownership is proven is refused")
        r = await api.post(
            "/api/v1/scans",
            json={
                "scan_target_id": target["id"],
                "scan_policy_id": str(policy.id),
                "mission": "Review headers, cookies and CORS of the demo shop.",
            },
            headers=headers,
        )
        print(f"POST /scans -> {r.status_code} {r.json()['detail']}")

        step("3. Issue a DNS TXT challenge and publish it")
        r = await api.post(
            f"/api/v1/targets/{target['id']}/verification/challenge", headers=headers
        )
        challenge = r.json()
        print(f"TXT {challenge['record_name']} = {challenge['record_value']}")
        DNS_TXT[challenge["record_name"]] = [challenge["record_value"]]

        step("4. Verify ownership")
        r = await api.post(f"/api/v1/targets/{target['id']}/verify", headers=headers)
        print(
            f"check_result={r.json()['check_result']} status={r.json()['verification_status']} "
            f"expires={r.json()['verification_expires_at']}"
        )

        step("5. Start an authorized scan")
        r = await api.post(
            "/api/v1/scans",
            json={
                "scan_target_id": target["id"],
                "scan_policy_id": str(policy.id),
                "mission": "Review headers, cookies and CORS of the demo shop.",
            },
            headers=headers,
        )
        r.raise_for_status()
        scan = r.json()
        print(f"scan {scan['id']} -> {scan['status']} (enqueued: {scan['id'] in queued})")

        step("6. Worker executes the scan (mock planner, mock target, real policy)")
        outcome = await run_agent_scan(
            scan["id"],
            job_id=f"demo:{scan['id']}",
            deps=RunnerDeps(
                resolver=fake_resolve,
                transport=httpx.MockTransport(target_site),
                enqueue_ai=lambda *_: asyncio.sleep(0),
            ),
        )
        r = await api.get(f"/api/v1/scans/{scan['id']}", headers=headers)
        print(f"outcome={outcome} status={r.json()['status']} stats={r.json()['stats']}")

        step("7. Evidence-backed findings")
        r = await api.get(
            f"/api/v1/scans/{scan['id']}/findings?include_evidence=true", headers=headers
        )
        for f in r.json():
            print(f"[{f['severity']:>6}] {f['title']}  ({f['plugin_id']})")

        step("8. Deterministic report")
        OUTPUT.mkdir(exist_ok=True)
        for fmt in ("json", "html"):
            r = await api.get(
                f"/api/v1/scans/{scan['id']}/report?format={fmt}&download=true", headers=headers
            )
            path = OUTPUT / f"report-{scan['id']}.{fmt}"
            path.write_text(r.text, encoding="utf-8")
            print(f"{fmt}: {path} (sha256 {r.headers['x-report-sha256'][:16]}...)")
        summary = json.loads((OUTPUT / f"report-{scan['id']}.json").read_text())["summary"]
        print(f"summary: {summary}")

        step("9. Cancellation")
        r = await api.post(
            "/api/v1/scans",
            json={
                "scan_target_id": target["id"],
                "scan_policy_id": str(policy.id),
                "mission": "Second scan that will be cancelled before it runs.",
            },
            headers=headers,
        )
        second = r.json()
        r = await api.post(f"/api/v1/scans/{second['id']}/cancel", headers=headers)
        print(f"cancel -> {r.json()['status']}")
        outcome = await run_agent_scan(
            second["id"], job_id="demo:late-job", deps=RunnerDeps(resolver=fake_resolve)
        )
        print(f"late worker delivery -> {outcome} (no requests sent)")

    print(f"\nDone. Log in to the web UI as {settings.seed_admin_email} to inspect the results.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
