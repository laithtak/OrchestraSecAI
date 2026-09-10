from typing import Any, Literal

from pydantic import BaseModel, Field

from orchestrasecai.checks.base import FindingDraft


class ToolCall(BaseModel):
    tool: Literal["passive_crawl", "run_check", "active_probe", "lookup_cve", "generate_poc"]
    params: dict[str, Any] = Field(default_factory=dict)


class ToolCallPlan(BaseModel):
    reasoning: str
    calls: list[ToolCall] = Field(default_factory=list)


class ToolResult(BaseModel):
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    success: bool
    findings: list[FindingDraft] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0

    model_config = {"arbitrary_types_allowed": True}


class CritiqueResult(BaseModel):
    reasoning: str
    status: Literal["replan", "continue", "complete"]
    follow_up_hints: list[str] = Field(default_factory=list)
