from unittest.mock import AsyncMock, patch

import pytest

from orchestrasecai.observability.context import bind_context, clear_context
from orchestrasecai.observability.tracing import enqueue_with_context


@pytest.mark.asyncio
async def test_enqueue_with_context_passes_carrier_and_request_id():
    bind_context(request_id="req-abc")
    pool = AsyncMock()
    pool.enqueue_job = AsyncMock(return_value=None)

    with patch(
        "orchestrasecai.observability.tracing.inject_trace_carrier",
        return_value={"traceparent": "00-abc-def-01"},
    ):
        await enqueue_with_context(pool, "run_scan_task", "scan-123")

    pool.enqueue_job.assert_awaited_once()
    args, kwargs = pool.enqueue_job.await_args
    assert args == ("run_scan_task", "scan-123")
    assert kwargs["request_id"] == "req-abc"
    assert kwargs["otel_carrier"] == {"traceparent": "00-abc-def-01"}
    clear_context()
