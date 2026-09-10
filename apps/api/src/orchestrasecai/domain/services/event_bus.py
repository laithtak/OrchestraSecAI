import json

from redis.asyncio import Redis

from orchestrasecai.config import get_settings

settings = get_settings()


async def publish_event(scan_id: str, event: str, data: dict) -> None:
    redis = Redis.from_url(settings.redis_url)
    channel = f"scan:{scan_id}:events"
    payload = {"event": event, **data}
    await redis.publish(channel, json.dumps(payload))
    await redis.aclose()
