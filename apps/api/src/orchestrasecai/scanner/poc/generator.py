"""PoC draft generator using LLM output.

Drafts are untrusted generated content: they are stored as AI analyses (never as
scanner evidence), are never executed, and are only produced for findings that belong
to the requesting scan.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.ai.client import LLMClient
from orchestrasecai.config import get_settings
from orchestrasecai.persistence.tables.core import AiAnalysis, Finding, FindingEvidence, Scan

PROMPT_VERSION = "poc_draft/inline-v1"


def _text(value: Any, limit: int) -> str:
    return str(value)[:limit] if value is not None else ""


class PocGenerator:
    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()

    async def generate(self, db: AsyncSession, scan: Scan, finding_id: UUID) -> dict[str, Any]:
        r = await db.execute(
            select(Finding).where(
                Finding.id == finding_id,
                Finding.scan_id == scan.id,
                Finding.org_id == scan.org_id,
            )
        )
        finding = r.scalar_one_or_none()
        if not finding:
            raise ValueError("Finding not found")

        r = await db.execute(
            select(FindingEvidence).where(FindingEvidence.finding_id == finding_id)
        )
        evidence = [
            {"type": e.evidence_type, "payload": e.payload} for e in r.scalars().all()
        ]

        system = (
            "You generate safe reproduction steps for security findings. "
            "Output JSON with keys: curl_command, httpie_command, steps (list of strings)."
        )
        user = (
            f"Finding: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"Location: {finding.location}\n"
            f"Evidence: {evidence}"
        )
        result = await self.llm.complete(system, user)
        steps = result.get("steps")
        poc_payload = {
            "finding_id": str(finding_id),
            "curl_command": _text(result.get("curl_command"), 2000),
            "httpie_command": _text(result.get("httpie_command"), 2000),
            "steps": [_text(s, 500) for s in steps[:20]]
            if isinstance(steps, list)
            else ["Review finding evidence and reproduce manually."],
            "untrusted_generated_content": True,
        }
        settings = get_settings()
        db.add(
            AiAnalysis(
                scan_id=scan.id,
                analysis_type="poc_draft",
                model_name="mock" if settings.mock_ai else settings.vllm_model,
                prompt_version=PROMPT_VERSION,
                result=poc_payload,
                status="completed",
            )
        )
        await db.flush()
        return poc_payload
