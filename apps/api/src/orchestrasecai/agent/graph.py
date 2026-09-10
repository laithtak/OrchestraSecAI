"""LangGraph three-node scan orchestrator: Planner → Executor → Critic."""

from __future__ import annotations

from typing import Any, Literal

from langgraph.graph import END, StateGraph

from orchestrasecai.agent.llm import AgentLLM
from orchestrasecai.agent.nodes.critic import critic_node
from orchestrasecai.agent.nodes.executor import executor_node
from orchestrasecai.agent.nodes.planner import planner_node
from orchestrasecai.agent.state import AgentState
from orchestrasecai.scanner.tools.layer import ScanToolLayer


def _merge_trace(existing: list[dict], new: list[dict]) -> list[dict]:
    return existing + new


def build_agent_graph(
    tool_layer: ScanToolLayer,
    llm: AgentLLM | None = None,
):
    llm = llm or AgentLLM()

    async def planner(state: AgentState) -> dict[str, Any]:
        result = await planner_node(state, llm=llm)
        merged = _merge_trace(state.get("trace_entries", []), result.pop("trace_entries", []))
        result["trace_entries"] = merged
        await _on_plan_created(state, result.get("plan"))
        return result

    async def executor(state: AgentState) -> dict[str, Any]:
        result = await executor_node(state, tool_layer)
        merged = _merge_trace(state.get("trace_entries", []), result.pop("trace_entries", []))
        result["trace_entries"] = merged
        return result

    async def critic(state: AgentState) -> dict[str, Any]:
        result = await critic_node(state, llm=llm)
        merged = _merge_trace(state.get("trace_entries", []), result.pop("trace_entries", []))
        result["trace_entries"] = merged
        return result

    def route_after_critic(state: AgentState) -> Literal["planner", "end"]:
        if state.get("complete"):
            return "end"
        return "planner"

    graph = StateGraph(AgentState)
    graph.add_node("planner", planner)
    graph.add_node("executor", executor)
    graph.add_node("critic", critic)
    graph.set_entry_point("planner")
    graph.add_edge("planner", "executor")
    graph.add_edge("executor", "critic")
    graph.add_conditional_edges("critic", route_after_critic, {"planner": "planner", "end": END})
    return graph.compile()


async def _on_plan_created(state: AgentState, plan) -> None:
    if plan is None:
        return
    from orchestrasecai.domain.services.event_bus import publish_event

    try:
        await publish_event(
            state["scan_id"],
            "agent.plan_created",
            {
                "iteration": state.get("iteration", 0) + 1,
                "calls_count": len(plan.calls),
                "reasoning": plan.reasoning[:500],
            },
        )
    except Exception:
        pass
