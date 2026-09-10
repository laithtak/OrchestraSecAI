"""Executor node — runs ToolCallPlan via ScanToolLayer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from orchestrasecai.agent.schemas import ToolResult
from orchestrasecai.agent.state import AgentState
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.scanner.tools.layer import ScanToolLayer


async def executor_node(
    state: AgentState,
    tool_layer: ScanToolLayer,
) -> dict[str, Any]:
    plan = state.get("plan")
    if not plan or not plan.calls:
        return {"tool_results": [], "trace_entries": []}

    results: list[ToolResult] = []
    trace_entries: list[dict[str, Any]] = []
    findings_summary = list(state.get("findings_summary", []))
    base_seq = len(state.get("trace_entries", []))

    for i, call in enumerate(plan.calls):
        result = await tool_layer.execute(call.tool, call.params)
        results.append(result)

        for draft in result.findings:
            findings_summary.append({
                "plugin_id": draft.plugin_id,
                "severity": draft.severity,
                "title": draft.title,
                "location": draft.location,
            })

        entry = {
            "seq": base_seq + i + 1,
            "type": "tool_call",
            "iteration": state.get("iteration", 1),
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": {
                "tool": call.tool,
                "params": call.params,
                "success": result.success,
                "error": result.error,
                "findings_count": len(result.findings),
                "duration_ms": result.duration_ms,
            },
        }
        trace_entries.append(entry)

        await publish_event(
            state["scan_id"],
            "agent.tool_executed",
            {
                "tool": call.tool,
                "success": result.success,
                "iteration": state.get("iteration", 1),
            },
        )

    return {
        "tool_results": results,
        "findings_summary": findings_summary,
        "trace_entries": trace_entries,
    }
