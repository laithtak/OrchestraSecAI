from fastapi import APIRouter
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from orchestrasecai.config import get_settings
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.persistence.session import engine

router = APIRouter(tags=["health"])
logger = get_logger(__name__)


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
    except (SQLAlchemyError, OSError, TimeoutError) as exc:
        logger.warning("readiness_database_failed", error_type=type(exc).__name__)
    try:
        r = Redis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        checks["redis"] = True
    except (RedisError, OSError, TimeoutError) as exc:
        logger.warning("readiness_redis_failed", error_type=type(exc).__name__)
    ok = all(checks.values())
    return {"status": "ready" if ok else "degraded", "checks": checks}
