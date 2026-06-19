import time
import uuid
from datetime import UTC, datetime
from uuid import UUID

from fastapi import Request
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from orchestrasecai.config import get_settings
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.observability.metrics import rate_limit_exceeded_total

logger = get_logger(__name__)

WINDOW_SECONDS = 60
DAY_SECONDS = 86400

_DAILY_COUNTER_LUA = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, ttl)
end
if count > limit then
    return 0
end
return limit - count + 1
"""

_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
    return 0
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window) + 1)
return limit - count - 1
"""


class RateLimitScripts:
    def __init__(self, sliding_window, daily_counter):
        self.sliding_window = sliding_window
        self.daily_counter = daily_counter


async def register_rate_limit_scripts(redis: Redis) -> RateLimitScripts:
    sliding = redis.register_script(_SLIDING_WINDOW_LUA)
    daily = redis.register_script(_DAILY_COUNTER_LUA)
    return RateLimitScripts(sliding_window=sliding, daily_counter=daily)


def client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trusted_proxy_depth > 0:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            hops = [h.strip() for h in forwarded.split(",") if h.strip()]
            if hops:
                idx = max(0, len(hops) - settings.trusted_proxy_depth - 1)
                return hops[idx]
    return request.client.host if request.client else "unknown"


def _redis_unavailable_response(settings) -> JSONResponse | None:
    if settings.rate_limit_fail_open:
        return None
    return JSONResponse(
        status_code=503,
        content={"detail": "Rate limit service unavailable"},
    )


async def check_scan_daily_limit(
    redis: Redis,
    org_id: UUID,
    scripts: RateLimitScripts | None = None,
) -> tuple[bool, int | None]:
    """Return (allowed, remaining) for org daily scan creation limit."""
    date_key = datetime.now(UTC).date().isoformat()
    redis_key = f"rate_limit:org:{org_id}:scans:{date_key}"
    limit = get_settings().rate_limit_scans_per_day
    settings = get_settings()
    try:
        if scripts is not None:
            result = await scripts.daily_counter(keys=[redis_key], args=[str(limit), str(DAY_SECONDS)])
        else:
            result = await redis.eval(_DAILY_COUNTER_LUA, 1, redis_key, str(limit), str(DAY_SECONDS))
        remaining = int(result)
        return remaining > 0, remaining if remaining > 0 else 0
    except Exception as exc:
        logger.warning("scan_daily_limit_check_failed", org_id=str(org_id), error=str(exc))
        if settings.rate_limit_fail_open:
            return True, None
        return False, 0


async def _is_allowed(
    redis: Redis,
    key: str,
    limit: int,
    window: float,
    scripts: RateLimitScripts | None = None,
) -> tuple[bool, int]:
    now = time.time()
    member = f"{now}:{uuid.uuid4()}"
    if scripts is not None:
        result = await scripts.sliding_window(
            keys=[key],
            args=[str(now), str(window), str(limit), member],
        )
    else:
        result = await redis.eval(
            _SLIDING_WINDOW_LUA,
            1,
            key,
            str(now),
            str(window),
            str(limit),
            member,
        )
    remaining = int(result)
    return remaining > 0, remaining


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api/v1"):
            return await call_next(request)

        settings = get_settings()
        ip = client_ip(request)
        redis_key = f"rate_limit:ip:{ip}"
        limit = settings.rate_limit_requests_per_minute
        scripts: RateLimitScripts | None = getattr(request.app.state, "rate_limit_scripts", None)

        try:
            redis: Redis | None = getattr(request.app.state, "redis", None)
            if redis is None:
                raise RuntimeError("Redis client not initialized on app.state")
            allowed, remaining = await _is_allowed(redis, redis_key, limit, WINDOW_SECONDS, scripts)
            if not allowed:
                rate_limit_exceeded_total.labels(limiter="ip").inc()
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={
                        "Retry-After": str(WINDOW_SECONDS),
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                    },
                )
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            return response
        except Exception as exc:
            logger.warning("rate_limit_check_failed", ip=ip, error=str(exc))
            unavailable = _redis_unavailable_response(settings)
            if unavailable is not None:
                return unavailable

        return await call_next(request)
