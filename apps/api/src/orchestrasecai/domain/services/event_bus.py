import json

from redis.asyncio import Redis
from redis.exceptions import RedisError

from orchestrasecai.config import get_settings
from orchestrasecai.observability.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


async def publish_event(scan_id: str, event: str, data: dict) -> None:
    """Publish a live progress event. Best-effort: durable state lives in PostgreSQL."""
    channel = f"scan:{scan_id}:events"
    payload = {"event": event, **data}
    try:
        redis = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        try:
            await redis.publish(channel, json.dumps(payload, default=str))
        finally:
            await redis.aclose()
    except (RedisError, OSError) as exc:
        logger.warning("scan_event_publish_failed", scan_event=event, error_type=type(exc).__name__)
