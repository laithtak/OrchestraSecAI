from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from orchestrasecai.config import get_settings
from orchestrasecai.persistence.session import engine
from orchestrasecai.persistence.tables.core import (
    Organization,
    PlanType,
    Project,
    ScanPolicy,
    User,
    UserRole,
)
from orchestrasecai.security.auth import hash_password

_settings = get_settings()
_factory = async_sessionmaker(engine, expire_on_commit=False)
_seeded = False


async def run_seed() -> None:
    global _seeded
    if not _settings.seed_enabled:
        return
    if _seeded:
        return
    async with _factory() as session:
        r = await session.execute(select(Organization).limit(1))
        if r.scalar_one_or_none():
            _seeded = True
            return
        org = Organization(name="Default Organization", slug="default", plan=PlanType.free)
        session.add(org)
        await session.flush()
        user = User(
            org_id=org.id,
            email=_settings.seed_admin_email,
            password_hash=hash_password(_settings.seed_admin_password),
            role=UserRole.owner,
            is_active=True,
        )
        session.add(user)
        policy = ScanPolicy(org_id=org.id, name="Default Policy", max_pages=50, max_depth=3)
        session.add(policy)
        project = Project(org_id=org.id, name="Default Project", description="MVP default project")
        session.add(project)
        await session.commit()
    _seeded = True
