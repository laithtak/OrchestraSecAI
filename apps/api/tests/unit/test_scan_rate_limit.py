from uuid import uuid4

import pytest

from orchestrasecai.api.middleware.rate_limit import RateLimitScripts, check_scan_daily_limit


class FakeScript:
    def __init__(self, results: list[int]):
        self._results = results
        self.calls = 0

    async def __call__(self, *, keys, args):
        result = self._results[min(self.calls, len(self._results) - 1)]
        self.calls += 1
        return result


class FakeRedis:
    def __init__(self, results: list[int]):
        self._results = results
        self.calls = 0

    async def eval(self, *_args, **_kwargs):
        result = self._results[min(self.calls, len(self._results) - 1)]
        self.calls += 1
        return result


@pytest.mark.asyncio
async def test_scan_daily_limit_allows_under_cap(monkeypatch):
    monkeypatch.setattr(
        "orchestrasecai.api.middleware.rate_limit.get_settings",
        lambda: type("S", (), {"rate_limit_scans_per_day": 50, "rate_limit_fail_open": True})(),
    )
    script = FakeScript([50, 49, 48])
    scripts = RateLimitScripts(sliding_window=FakeScript(1), daily_counter=script)
    org_id = uuid4()

    allowed, _ = await check_scan_daily_limit(FakeRedis([1]), org_id, scripts)
    assert allowed is True
    allowed, _ = await check_scan_daily_limit(FakeRedis([1]), org_id, scripts)
    assert allowed is True


@pytest.mark.asyncio
async def test_scan_daily_limit_blocks_over_cap(monkeypatch):
    monkeypatch.setattr(
        "orchestrasecai.api.middleware.rate_limit.get_settings",
        lambda: type("S", (), {"rate_limit_scans_per_day": 2, "rate_limit_fail_open": True})(),
    )
    script = FakeScript([2, 1, 0])
    scripts = RateLimitScripts(sliding_window=FakeScript(1), daily_counter=script)
    org_id = uuid4()

    allowed, _ = await check_scan_daily_limit(FakeRedis([1]), org_id, scripts)
    assert allowed is True
    allowed, _ = await check_scan_daily_limit(FakeRedis([1]), org_id, scripts)
    assert allowed is True
    allowed, _ = await check_scan_daily_limit(FakeRedis([1]), org_id, scripts)
    assert allowed is False


@pytest.mark.asyncio
async def test_scan_daily_limit_fails_open_on_error(monkeypatch):
    monkeypatch.setattr(
        "orchestrasecai.api.middleware.rate_limit.get_settings",
        lambda: type("S", (), {"rate_limit_scans_per_day": 50, "rate_limit_fail_open": True})(),
    )

    class BrokenScript:
        async def __call__(self, *, keys, args):
            raise ConnectionError("redis down")

    scripts = RateLimitScripts(sliding_window=FakeScript(1), daily_counter=BrokenScript())
    org_id = uuid4()
    allowed, remaining = await check_scan_daily_limit(FakeRedis([]), org_id, scripts)
    assert allowed is True
    assert remaining is None
