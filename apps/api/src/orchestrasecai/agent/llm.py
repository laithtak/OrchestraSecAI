"""LLM wrapper for structured agent output."""

from __future__ import annotations

import json
from typing import TypeVar

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from orchestrasecai.agent.schemas import CritiqueResult, ToolCall, ToolCallPlan
from orchestrasecai.ai.prompts.loader import render_prompt
from orchestrasecai.config import get_settings

settings = get_settings()
T = TypeVar("T", bound=BaseModel)


class AgentLLM:
    def __init__(self) -> None:
        self.mock = settings.mock_ai
        self._client: ChatOpenAI | None = None

    def _chat(self) -> ChatOpenAI:
        if self._client is None:
            self._client = ChatOpenAI(
                base_url=settings.vllm_base_url,
                api_key="not-needed",
                model=settings.vllm_model,
                temperature=0.2,
            )
        return self._client

    async def structured(self, model_cls: type[T], system: str, user: str) -> T:
        if self.mock:
            return self._mock_structured(model_cls, user)
        llm = self._chat().with_structured_output(model_cls)
        result = await llm.ainvoke([SystemMessage(content=system), HumanMessage(content=user)])
        return result  # type: ignore[return-value]

    def _mock_structured(self, model_cls: type[T], user: str) -> T:
        if model_cls is ToolCallPlan:
            iteration = 1
            if "iteration: 2" in user or "iteration: 3" in user:
                iteration = 2
            if iteration == 1:
                return ToolCallPlan(  # type: ignore[return-value]
                    reasoning="Mock plan: crawl target then run header and cors checks.",
                    calls=[
                        ToolCall(tool="passive_crawl", params={}),
                        ToolCall(
                            tool="run_check",
                            params={"plugin_id": "header", "target_url": _extract_url(user)},
                        ),
                        ToolCall(
                            tool="run_check",
                            params={"plugin_id": "cors", "target_url": _extract_url(user)},
                        ),
                    ],
                )
            return ToolCallPlan(  # type: ignore[return-value]
                reasoning="Mock plan: no further tools needed.",
                calls=[],
            )
        if model_cls is CritiqueResult:
            if "iteration: 1" in user:
                return CritiqueResult(  # type: ignore[return-value]
                    reasoning="Initial checks complete; one more planning pass.",
                    status="continue",
                    follow_up_hints=["Review CORS and header findings"],
                )
            return CritiqueResult(  # type: ignore[return-value]
                reasoning="Mock critique: mission objectives met.",
                status="complete",
            )
        raise ValueError(f"No mock for {model_cls}")

    async def plan(self, **kwargs) -> ToolCallPlan:
        system, user, _ = render_prompt("agent/planner", "v1", **kwargs)
        return await self.structured(ToolCallPlan, system, user)

    async def critique(self, **kwargs) -> CritiqueResult:
        system, user, _ = render_prompt("agent/critic", "v1", **kwargs)
        return await self.structured(CritiqueResult, system, user)


def _extract_url(user: str) -> str:
    for line in user.splitlines():
        if line.startswith("Target URL:"):
            return line.split(":", 1)[1].strip()
    return "https://example.com"
