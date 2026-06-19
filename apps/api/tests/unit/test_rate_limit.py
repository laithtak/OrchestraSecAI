from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from orchestrasecai.api.middleware.rate_limit import RateLimitMiddleware, RateLimitScripts, client_ip


class FakeScript:
    def __init__(self, result: int):
        self._result = result
        self.calls = []

    async def __call__(self, *, keys, args):
        self.calls.append((keys, args))
        return self._result


def _make_app(redis: AsyncMock | None, scripts: RateLimitScripts | None = None) -> FastAPI:
    app = FastAPI()
    app.state.redis = redis
    app.state.rate_limit_scripts = scripts

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    @app.get("/docs")
    async def docs():
        return {"docs": True}

    app.add_middleware(RateLimitMiddleware)
    return app


@pytest.mark.asyncio
async def test_under_limit_allows_request():
    redis = AsyncMock()
    scripts = RateLimitScripts(
        sliding_window=FakeScript(5),
        daily_counter=FakeScript(1),
    )
    app = _make_app(redis, scripts)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"] == "120"
    assert response.headers["X-RateLimit-Remaining"] == "5"
    assert len(scripts.sliding_window.calls) == 1


@pytest.mark.asyncio
async def test_over_limit_returns_429():
    redis = AsyncMock()
    scripts = RateLimitScripts(
        sliding_window=FakeScript(0),
        daily_counter=FakeScript(1),
    )
    app = _make_app(redis, scripts)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 429
    assert response.json()["detail"] == "Rate limit exceeded"
    assert response.headers["Retry-After"] == "60"
    assert response.headers["X-RateLimit-Remaining"] == "0"


@pytest.mark.asyncio
async def test_redis_failure_fails_open():
    redis = AsyncMock()
    scripts = RateLimitScripts(
        sliding_window=FakeScript(1),
        daily_counter=FakeScript(1),
    )
    scripts.sliding_window._result = 1

    async def broken_script(*, keys, args):
        raise ConnectionError("redis down")

    scripts.sliding_window = broken_script
    app = _make_app(redis, scripts)

    mock_logger = MagicMock()
    with patch("orchestrasecai.api.middleware.rate_limit.logger", mock_logger):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/health")

    assert response.status_code == 200
    mock_logger.warning.assert_called_once()
    assert mock_logger.warning.call_args[0][0] == "rate_limit_check_failed"


@pytest.mark.asyncio
async def test_missing_redis_client_fails_open():
    app = FastAPI()

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    app.add_middleware(RateLimitMiddleware)

    mock_logger = MagicMock()
    with patch("orchestrasecai.api.middleware.rate_limit.logger", mock_logger):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/health")

    assert response.status_code == 200
    mock_logger.warning.assert_called_once()


@pytest.mark.asyncio
async def test_redis_failure_fails_closed():
    redis = AsyncMock()

    async def broken_script(*, keys, args):
        raise ConnectionError("redis down")

    scripts = RateLimitScripts(sliding_window=broken_script, daily_counter=FakeScript(1))
    app = _make_app(redis, scripts)

    mock_settings = MagicMock()
    mock_settings.rate_limit_requests_per_minute = 120
    mock_settings.rate_limit_fail_open = False
    mock_settings.trusted_proxy_depth = 0

    with patch(
        "orchestrasecai.api.middleware.rate_limit.get_settings",
        return_value=mock_settings,
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/health")

    assert response.status_code == 503


@pytest.mark.asyncio
async def test_non_api_path_skips_rate_limit():
    redis = AsyncMock()
    scripts = RateLimitScripts(
        sliding_window=FakeScript(1),
        daily_counter=FakeScript(1),
    )
    app = _make_app(redis, scripts)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/docs")

    assert response.status_code == 200
    assert scripts.sliding_window.calls == []


def test_client_ip_uses_forwarded_for_when_trusted():
    request = MagicMock()
    request.client.host = "10.0.0.1"
    request.headers = {"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}

    mock_settings = MagicMock()
    mock_settings.trusted_proxy_depth = 1

    with patch(
        "orchestrasecai.api.middleware.rate_limit.get_settings",
        return_value=mock_settings,
    ):
        assert client_ip(request) == "1.2.3.4"


@pytest.mark.asyncio
async def test_limit_read_from_settings():
    redis = AsyncMock()
    script = FakeScript(3)
    scripts = RateLimitScripts(sliding_window=script, daily_counter=FakeScript(1))
    app = _make_app(redis, scripts)

    mock_settings = MagicMock()
    mock_settings.rate_limit_requests_per_minute = 42
    mock_settings.rate_limit_fail_open = True
    mock_settings.trusted_proxy_depth = 0

    with patch(
        "orchestrasecai.api.middleware.rate_limit.get_settings",
        return_value=mock_settings,
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            await client.get("/api/v1/health")

    _keys, args = script.calls[0]
    assert args[2] == "42"
