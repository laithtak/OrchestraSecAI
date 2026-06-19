import json
from datetime import UTC, datetime
from uuid import UUID

from jinja2 import Template
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from orchestrasecai.ai.client import LLMClient, load_prompt
from orchestrasecai.ai.embeddings import find_similar, upsert_finding_embedding
from orchestrasecai.config import get_settings
from orchestrasecai.domain.services.scan_runner import publish_event
from orchestrasecai.persistence.tables import AiAnalysis, Finding, Report, Scan
from orchestrasecai.persistence.tables.core import ReportFormat, ScanStatus

settings = get_settings()


def _render_prompt(prompt_cfg: dict, **kwargs) -> tuple[str, str]:
    system = prompt_cfg["system"]
    user = Template(prompt_cfg["user_template"]).render(**kwargs)
    return system, user


async def run_full_ai_pipeline(scan_id: str) -> None:
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    llm = LLMClient()

    async with session_factory() as db:
        scan = await db.get(Scan, UUID(scan_id))
        if not scan:
            return
        result = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
        findings = list(result.scalars().all())

        findings_data = [
            {
                "id": str(f.id),
                "plugin_id": f.plugin_id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "location": f.location,
            }
            for f in findings
        ]
        findings_json = json.dumps(findings_data, indent=2)

        for f in findings:
            text = f"{f.title} {f.description} {f.plugin_id}"
            await upsert_finding_embedding(str(scan.org_id), str(f.id), text)
            similar = await find_similar(str(scan.org_id), text)
            if similar:
                f.location = {**f.location, "similar_findings": similar}

        pipelines = [
            ("explain", "explain"),
            ("prioritize", "prioritize"),
            ("executive_summary", "executive_summary"),
            ("technical_report", "technical_report"),
        ]
        analysis_results: dict[str, dict] = {}

        for folder, analysis_type in pipelines:
            cfg = load_prompt(folder)
            system, user = _render_prompt(
                cfg,
                findings_json=findings_json,
                stats_json=json.dumps(scan.stats or {}),
            )
            result_data = await llm.complete(system, user)
            analysis_results[analysis_type] = result_data
            db.add(
                AiAnalysis(
                    scan_id=scan.id,
                    analysis_type=analysis_type,
                    model_name=settings.vllm_model if not settings.mock_ai else "mock",
                    prompt_version=cfg.get("version", "v1"),
                    result=result_data,
                )
            )
            await publish_event(
                scan_id,
                "ai.analysis_completed",
                {"analysis_type": analysis_type},
            )

        html = _render_html_report(scan, findings, analysis_results)
        json_report = json.dumps(
            {
                "scan_id": str(scan.id),
                "generated_at": datetime.now(UTC).isoformat(),
                "stats": scan.stats,
                "findings": findings_data,
                "ai": analysis_results,
            },
            indent=2,
        )
        db.add(Report(scan_id=scan.id, format=ReportFormat.html, content=html, version=1))
        db.add(Report(scan_id=scan.id, format=ReportFormat.json, content=json_report, version=1))

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.now(UTC)
        await db.commit()
        await publish_event(scan_id, "scan.status_changed", {"status": "completed"})

    await engine.dispose()


def _render_html_report(scan: Scan, findings: list, ai: dict) -> str:
    exec_summary = ai.get("executive_summary", {})
    tech = ai.get("technical_report", {})
    rows = "".join(
        f"<tr><td>{f.severity.value if hasattr(f.severity, 'value') else f.severity}</td><td>{f.title}</td><td>{f.plugin_id}</td></tr>"
        for f in findings
    )
    return f"""<!DOCTYPE html>
<html><head><title>OrchestraSecAI Report - {scan.id}</title>
<style>body{{font-family:sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:8px}}</style></head>
<body>
<h1>OrchestraSecAI Security Report</h1>
<p><strong>Scan ID:</strong> {scan.id}</p>
<p><strong>Status:</strong> {scan.status}</p>
<p><em>Passive-only scan. Findings require authorized remediation.</em></p>
<h2>Executive Summary</h2>
<p>{exec_summary.get('executive_summary', 'N/A')}</p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Plugin</th></tr>{rows}</table>
<h2>Technical Report</h2>
<pre>{tech.get('technical_report', 'N/A')}</pre>
</body></html>"""
