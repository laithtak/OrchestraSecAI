"""Tests for LangGraph agent routing."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from orchestrasecai.agent.graph import build_agent_graph
from orchestrasecai.agent.llm import AgentLLM
from orchestrasecai.agent.schemas import CritiqueResult, ToolCall, ToolCallPlan, ToolResult
from orchestrasecai.agent.state import AgentState


@pytest.mark.asyncio
@patch("orchestrasecai.agent.nodes.critic.publish_event", new_callable=AsyncMock)
@patch("orchestrasecai.agent.nodes.executor.publish_event", new_callable=AsyncMock)
@patch("orchestrasecai.domain.services.event_bus.publish_event", new_callable=AsyncMock)
async def test_graph_completes_on_critique_complete(_eb, _ex, _cr):
    llm = AgentLLM()
    llm.mock = True

    tool_layer = MagicMock()
    tool_layer.execute = AsyncMock(
        return_value=ToolResult(tool="passive_crawl", params={}, success=True, duration_ms=10)
    )

    graph = build_agent_graph(tool_layer, llm=llm)
    state: AgentState = {
        "scan_id": "test-scan",
        "session_id": "sess-1",
        "mission": "Find header issues on the target application.",
        "target_url": "https://example.com",
        "policy": {"max_pages": 5, "max_depth": 1, "requests_per_second": 1.0},
        "findings_summary": [],
        "iteration": 0,
        "max_iterations": 5,
        "trace_entries": [],
        "follow_up_hints": [],
        "complete": False,
    }

    final = await graph.ainvoke(state)
    assert final.get("complete") is True
    assert final.get("iteration", 0) >= 1
    assert len(final.get("trace_entries", [])) >= 3


@pytest.mark.asyncio
@patch("orchestrasecai.agent.nodes.critic.publish_event", new_callable=AsyncMock)
@patch("orchestrasecai.agent.nodes.executor.publish_event", new_callable=AsyncMock)
@patch("orchestrasecai.domain.services.event_bus.publish_event", new_callable=AsyncMock)
async def test_graph_respects_max_iterations(_eb, _ex, _cr):
    llm = MagicMock()
    llm.plan = AsyncMock(
        return_value=ToolCallPlan(
            reasoning="keep going",
            calls=[ToolCall(tool="passive_crawl", params={})],
        )
    )
    llm.critique = AsyncMock(
        return_value=CritiqueResult(reasoning="need more", status="continue")
    )

    tool_layer = MagicMock()
    tool_layer.execute = AsyncMock(
        return_value=ToolResult(tool="passive_crawl", params={}, success=True, duration_ms=5)
    )

    graph = build_agent_graph(tool_layer, llm=llm)
    state: AgentState = {
        "scan_id": "test-scan",
        "session_id": "sess-1",
        "mission": "Enumerate all vulnerabilities exhaustively.",
        "target_url": "https://example.com",
        "policy": {},
        "findings_summary": [],
        "iteration": 0,
        "max_iterations": 2,
        "trace_entries": [],
        "complete": False,
    }

    final = await graph.ainvoke(state)
    assert final.get("complete") is True
    assert final.get("termination_reason") == "max_iterations"
    assert final.get("iteration") == 2
