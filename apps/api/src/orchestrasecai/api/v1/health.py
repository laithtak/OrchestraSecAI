from fastapi import APIRouter
from redis.asyncio import Redis
from sqlalchemy import text

from orchestrasecai.config import get_settings
from orchestrasecai.persistence.session import engine

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.get("/ready")
async def ready():
    settings = get_settings()
    checks = {"database": False, "redis": False}
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        pass
    try:
        r = Redis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        checks["redis"] = True
    except Exception:
        pass
    ok = all(checks.values())
    return {"status": "ready" if ok else "degraded", "checks": checks}
