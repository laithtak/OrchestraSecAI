"""Optional AI enrichment for completed scans.

AI output is interpretation, not evidence. This pipeline:
* never changes scan status, findings or evidence;
* records every analysis (including failures) in ``ai_analyses`` with model/prompt;
* validates model output that references findings against the scan's real findings;
* re-renders the deterministic report with a separately labelled AI section.
If the model is unavailable the deterministic report generated at completion stands.
"""

import json
from datetime import UTC, datetime
from uuid import UUID

from jinja2 import Template
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from orchestrasecai.ai.client import LLMClient, load_prompt
from orchestrasecai.ai.embeddings import find_similar, upsert_finding_embedding
from orchestrasecai.config import get_settings
from orchestrasecai.domain.reporting import store_report
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.persistence.tables import AiAnalysis, Finding, Scan
from orchestrasecai.persistence.tables.core import ScanStatus

settings = get_settings()
logger = get_logger(__name__)
ENRICHABLE_STATES = (ScanStatus.completed, ScanStatus.timed_out)
PIPELINES = ("explain", "prioritize", "executive_summary", "technical_report")


def _render_prompt(prompt_cfg: dict, **kwargs) -> tuple[str, str]:
    system = prompt_cfg["system"]
    user = Template(prompt_cfg["user_template"]).render(**kwargs)
    return system, user


def _sanitize(analysis_type: str, result: dict, finding_ids: set[str]) -> dict:
    """Drop model claims that reference findings which do not exist in this scan."""
    if analysis_type == "prioritize" and isinstance(result.get("ranked_ids"), list):
        result = {
            **result,
            "ranked_ids": [i for i in result["ranked_ids"] if str(i) in finding_ids],
        }
    return result


async def run_full_ai_pipeline(scan_id: str, *, session_factory=None, llm=None) -> str:
    engine = None
    factory = session_factory
    if factory is None:
        engine = create_async_engine(settings.database_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
    llm = llm or LLMClient()
    model_name = "mock" if settings.mock_ai else settings.vllm_model

    try:
        async with factory() as db:
            scan = await db.get(Scan, UUID(scan_id))
            if not scan or scan.status not in ENRICHABLE_STATES:
                return "skipped"
            result = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
            findings = list(result.scalars().all())
            finding_ids = {str(f.id) for f in findings}
            findings_json = json.dumps(
                [
                    {
                        "id": str(f.id),
                        "plugin_id": f.plugin_id,
                        "severity": getattr(f.severity, "value", f.severity),
                        "title": f.title,
                        "description": f.description,
                        "location": f.location,
                    }
                    for f in findings
                ],
                indent=2,
            )

            similar: dict[str, list] = {}
            try:
                for f in findings:
                    text = f"{f.title} {f.description} {f.plugin_id}"
                    await upsert_finding_embedding(str(scan.org_id), str(f.id), text)
                    matches = await find_similar(str(scan.org_id), text)
                    if matches:
                        similar[str(f.id)] = matches
            except Exception as exc:  # noqa: BLE001 - embeddings are optional enrichment
                logger.warning("ai_embeddings_failed", error_type=type(exc).__name__)

            analyses: dict[str, dict] = {}
            for analysis_type in PIPELINES:
                cfg = load_prompt(analysis_type)
                system, user = _render_prompt(
                    cfg, findings_json=findings_json, stats_json=json.dumps(scan.stats or {})
                )
                status = "completed"
                try:
                    data = await llm.complete(system, user)
                    if not isinstance(data, dict):
                        raise TypeError("non-object model output")
                    data = _sanitize(analysis_type, data, finding_ids)
                    analyses[analysis_type] = data
                except Exception as exc:  # noqa: BLE001 - one failed analysis is not fatal
                    status = "failed"
                    data = {"error": "model_unavailable", "error_type": type(exc).__name__}
                    logger.warning(
                        "ai_analysis_failed",
                        analysis_type=analysis_type,
                        error_type=type(exc).__name__,
                    )
                db.add(
                    AiAnalysis(
                        scan_id=scan.id,
                        analysis_type=analysis_type,
                        model_name=model_name,
                        prompt_version=cfg.get("version", "v1"),
                        result=data,
                        status=status,
                    )
                )
            if similar:
                db.add(
                    AiAnalysis(
                        scan_id=scan.id,
                        analysis_type="similar_findings",
                        model_name="embeddings",
                        prompt_version="n/a",
                        result=similar,
                        status="completed",
                    )
                )
            await db.flush()

            if analyses:
                await store_report(
                    db,
                    scan,
                    ai_enrichment={
                        "model": model_name,
                        "generated_at": datetime.now(UTC).isoformat(),
                        "analyses": analyses,
                    },
                )
            await db.commit()
        await publish_event(
            scan_id, "ai.analysis_completed", {"analyses": sorted(analyses.keys())}
        )
        return "enriched" if analyses else "ai_unavailable"
    finally:
        if engine is not None:
            await engine.dispose()
