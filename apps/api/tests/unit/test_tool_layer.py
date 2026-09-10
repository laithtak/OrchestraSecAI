"""Tests for ScanToolLayer scope and ActiveProbeEngine."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from orchestrasecai.scanner.active.engine import ActiveProbeEngine
from orchestrasecai.scanner.tools.layer import ScanToolLayer
from orchestrasecai.persistence.tables.core import Scan, ScanPolicy, ScanTarget


@pytest.mark.asyncio
async def test_active_probe_rejects_unknown_technique():
    engine = ActiveProbeEngine(
        base_url="https://example.com",
        allowed_hosts=["example.com"],
    )
    result = await engine.probe("unknown_technique", "https://example.com/")
    assert result.success is False
    assert "Unknown technique" in (result.error or "")


@pytest.mark.asyncio
async def test_active_probe_rejects_out_of_scope_url():
    engine = ActiveProbeEngine(
        base_url="https://example.com",
        allowed_hosts=["example.com"],
    )
    result = await engine.probe("cors_origin_test", "https://evil.other.com/")
    assert result.success is False
    assert "out of scope" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_tool_layer_writes_audit_on_run_check():
    db = AsyncMock()
    db.refresh = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    db.add = MagicMock()
    db.get = AsyncMock(return_value=None)
    db.execute = AsyncMock()

    scan = Scan(
        id=uuid4(),
        org_id=uuid4(),
        scan_target_id=uuid4(),
        scan_policy_id=uuid4(),
        mission="Test mission for audit logging.",
    )
    target = ScanTarget(
        id=uuid4(),
        org_id=scan.org_id,
        project_id=uuid4(),
        base_url="https://example.com",
        allowed_hosts=["example.com"],
    )
    policy = ScanPolicy(
        id=uuid4(),
        org_id=scan.org_id,
        user_agent="test-agent",
        requests_per_second=10.0,
    )

    layer = ScanToolLayer(db, scan, target, policy, set())

    with patch(
        "orchestrasecai.scanner.tools.layer.write_audit_log",
        new_callable=AsyncMock,
    ) as audit_mock:
        with patch.object(layer, "_get_page_context", new_callable=AsyncMock) as page_mock:
            from orchestrasecai.checks.base import PageContext

            page_mock.return_value = PageContext(
                url="https://example.com",
                final_url="https://example.com",
                status_code=200,
                headers={},
                cookies=[],
                body_snippet="",
                depth=0,
            )
            with patch("orchestrasecai.scanner.tools.layer.build_registry") as reg_mock:
                reg_mock.return_value.get.return_value = None
                result = await layer.execute(
                    "run_check",
                    {"plugin_id": "header", "target_url": "https://example.com"},
                )
                audit_mock.assert_called_once()
                assert audit_mock.call_args.kwargs["action"] == "agent.tool_call"
                assert result.success is False
