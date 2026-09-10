"""PoC draft generator using LLM structured output."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.ai.client import LLMClient
from orchestrasecai.persistence.tables.core import Finding, FindingEvidence


class PocGenerator:
    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()

    async def generate(self, db: AsyncSession, finding_id: UUID) -> dict[str, Any]:
        finding = await db.get(Finding, finding_id)
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

        poc_payload = {
            "curl_command": result.get("curl_command", f"curl -i '{finding.location.get('url', '')}'"),
            "httpie_command": result.get("httpie_command", ""),
            "steps": result.get("steps", ["Review finding evidence and reproduce manually."]),
        }

        db.add(
            FindingEvidence(
                finding_id=finding_id,
                evidence_type="poc_draft",
                payload=poc_payload,
            )
        )
        await db.flush()
        return poc_payload
