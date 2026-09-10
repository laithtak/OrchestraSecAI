from typing import Any, TypedDict

from orchestrasecai.agent.schemas import CritiqueResult, ToolCallPlan, ToolResult


class AgentState(TypedDict, total=False):
    scan_id: str
    session_id: str
    mission: str
    target_url: str
    policy: dict[str, Any]
    findings_summary: list[dict[str, Any]]
    plan: ToolCallPlan | None
    tool_results: list[ToolResult]
    critique: CritiqueResult | None
    iteration: int
    max_iterations: int
    trace_entries: list[dict[str, Any]]
    follow_up_hints: list[str]
    termination_reason: str | None
    complete: bool
