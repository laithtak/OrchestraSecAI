from uuid import uuid4

import pytest

from orchestrasecai.api.services.report_tokens import (
    consume_report_view_token,
    create_report_view_token,
)


class FakeRedis:
    def __init__(self):
        self._store: dict[str, str] = {}

    async def set(self, key: str, value: str, ex: int | None = None):
        self._store[key] = value

    async def getdel(self, key: str) -> str | None:
        return self._store.pop(key, None)


@pytest.mark.asyncio
async def test_create_and_consume_report_token():
    redis = FakeRedis()
    scan_id = uuid4()
    org_id = uuid4()
    user_id = uuid4()

    token = await create_report_view_token(redis, scan_id, org_id, user_id, "html")
    payload = await consume_report_view_token(redis, token)

    assert payload is not None
    assert payload["scan_id"] == str(scan_id)
    assert payload["org_id"] == str(org_id)
    assert payload["format"] == "html"


@pytest.mark.asyncio
async def test_consume_report_token_single_use():
    redis = FakeRedis()
    scan_id = uuid4()
    org_id = uuid4()
    user_id = uuid4()

    token = await create_report_view_token(redis, scan_id, org_id, user_id, "html")
    first = await consume_report_view_token(redis, token)
    second = await consume_report_view_token(redis, token)

    assert first is not None
    assert second is None


@pytest.mark.asyncio
async def test_consume_invalid_token():
    redis = FakeRedis()
    assert await consume_report_view_token(redis, "missing") is None
