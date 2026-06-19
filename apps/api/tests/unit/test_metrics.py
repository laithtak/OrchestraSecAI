import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from orchestrasecai.observability.metrics import mount_metrics


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format():
    app = FastAPI()
    mount_metrics(app)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/metrics")

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "rate_limit_exceeded_total" in body
