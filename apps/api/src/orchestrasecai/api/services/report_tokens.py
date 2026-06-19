import json

import secrets

from uuid import UUID



from redis.asyncio import Redis



REPORT_TOKEN_TTL_SECONDS = 30

_KEY_PREFIX = "report_view:"





async def create_report_view_token(

    redis: Redis,

    scan_id: UUID,

    org_id: UUID,

    user_id: UUID,

    fmt: str,

) -> str:

    token = secrets.token_urlsafe(32)

    payload = {

        "scan_id": str(scan_id),

        "org_id": str(org_id),

        "user_id": str(user_id),

        "format": fmt,

    }

    await redis.set(

        f"{_KEY_PREFIX}{token}",

        json.dumps(payload),

        ex=REPORT_TOKEN_TTL_SECONDS,

    )

    return token





async def consume_report_view_token(redis: Redis, token: str) -> dict | None:

    raw = await redis.getdel(f"{_KEY_PREFIX}{token}")

    if not raw:

        return None

    return json.loads(raw)


