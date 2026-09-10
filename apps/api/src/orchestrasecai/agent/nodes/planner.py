"""Planner node — produces ToolCallPlan."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from orchestrasecai.agent.llm import AgentLLM
from orchestrasecai.agent.state import AgentState
from orchestrasecai.config import get_settings

settings = get_settings()


async def planner_node(state: AgentState, llm: AgentLLM | None = None) -> dict[str, Any]:
    llm = llm or AgentLLM()
    iteration = state.get("iteration", 0) + 1
    policy = state.get("policy", {})

    plan = await llm.plan(
        mission=state["mission"],
        target_url=state["target_url"],
        iteration=iteration,
        max_tools_per_plan=settings.agent_max_tools_per_plan,
        max_pages=policy.get("max_pages", 50),
        max_depth=policy.get("max_depth", 3),
        requests_per_second=policy.get("requests_per_second", 2.0),
        follow_up_hints=state.get("follow_up_hints", []),
        findings_summary=state.get("findings_summary", []),
    )

    calls = plan.calls[: settings.agent_max_tools_per_plan]
    plan = plan.model_copy(update={"calls": calls})

    entry = {
        "seq": len(state.get("trace_entries", [])) + 1,
        "type": "plan",
        "iteration": iteration,
        "timestamp": datetime.now(UTC).isoformat(),
        "payload": plan.model_dump(),
    }

    return {
        "plan": plan,
        "iteration": iteration,
        "trace_entries": [entry],
    }
