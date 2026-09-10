"""Mock-mode end-to-end agent loop test."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from orchestrasecai.agent.graph import build_agent_graph


from orchestrasecai.agent.llm import AgentLLM
from orchestrasecai.agent.schemas import ToolResult
from orchestrasecai.agent.state import AgentState


@pytest.mark.asyncio
@patch("orchestrasecai.agent.nodes.critic.publish_event", new_callable=AsyncMock)
@patch("orchestrasecai.agent.nodes.executor.publish_event", new_callable=AsyncMock)
@patch("orchestrasecai.domain.services.event_bus.publish_event", new_callable=AsyncMock)
async def test_mock_agent_loop_under_five_iterations(_eb, _ex, _cr):
    llm = AgentLLM()
    assert llm.mock is True

    tool_layer = MagicMock()
    tool_layer.execute = AsyncMock(
        side_effect=lambda tool, params: ToolResult(
            tool=tool,
            params=params,
            success=True,
            duration_ms=1,
        )
    )

    graph = build_agent_graph(tool_layer, llm=llm)
    state: AgentState = {
        "scan_id": "e2e-scan",
        "session_id": "sess-e2e",
        "mission": "Find CORS misconfigs and header issues on the login page.",
        "target_url": "https://example.com",
        "policy": {"max_pages": 10, "max_depth": 2, "requests_per_second": 2.0},
        "findings_summary": [],
        "iteration": 0,
        "max_iterations": 10,
        "trace_entries": [],
        "complete": False,
    }

    final = await graph.ainvoke(state)
    assert final.get("complete") is True
    assert final.get("iteration", 99) < 5
    types = {e["type"] for e in final.get("trace_entries", [])}
    assert "plan" in types
    assert "tool_call" in types
    assert "critique" in types
