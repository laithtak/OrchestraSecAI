"""Critic node — evaluates iteration and decides next step."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from orchestrasecai.agent.llm import AgentLLM
from orchestrasecai.agent.state import AgentState
from orchestrasecai.domain.services.event_bus import publish_event


async def critic_node(state: AgentState, llm: AgentLLM | None = None) -> dict[str, Any]:
    llm = llm or AgentLLM()
    iteration = state.get("iteration", 1)
    max_iterations = state.get("max_iterations", 10)

    tool_results = [
        {
            "tool": r.tool,
            "success": r.success,
            "error": r.error,
            "findings_count": len(r.findings),
        }
        for r in state.get("tool_results", [])
    ]

    critique = await llm.critique(
        mission=state["mission"],
        iteration=iteration,
        max_iterations=max_iterations,
        tool_results=tool_results,
        findings_summary=state.get("findings_summary", []),
    )

    complete = critique.status == "complete"
    termination_reason = None

    if iteration >= max_iterations and not complete:
        complete = True
        termination_reason = "max_iterations"
        critique = critique.model_copy(
            update={
                "status": "complete",
                "reasoning": f"{critique.reasoning} (forced: max_iterations reached)",
            }
        )

    entry = {
        "seq": len(state.get("trace_entries", [])) + 1,
        "type": "critique",
        "iteration": iteration,
        "timestamp": datetime.now(UTC).isoformat(),
        "payload": critique.model_dump(),
    }

    await publish_event(
        state["scan_id"],
        "agent.critique",
        {
            "status": critique.status,
            "iteration": iteration,
            "complete": complete,
        },
    )

    return {
        "critique": critique,
        "follow_up_hints": critique.follow_up_hints,
        "complete": complete,
        "termination_reason": termination_reason,
        "trace_entries": [entry],
    }
