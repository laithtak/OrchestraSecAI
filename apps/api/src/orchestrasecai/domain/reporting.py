"""Deterministic structured scan reports (no LLM, no GPU, no network).

The report is a pure function of persisted scan state: findings are ordered
deterministically and timestamps come from the scan record, so regenerating a report
for unchanged data yields byte-identical output. Scanner evidence and AI enrichment are
kept in separate sections; AI content is labelled non-authoritative and can never add,
remove or modify findings.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from jinja2 import Environment, select_autoescape
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from orchestrasecai.persistence.tables.core import (
    Finding,
    Report,
    ReportFormat,
    Scan,
    ScanTarget,
)

REPORT_SCHEMA_VERSION = "1.0"
SEVERITY_ORDER = ["high", "medium", "low", "info"]
DISCLAIMER = (
    "Findings are produced by deterministic OrchestraSecAI checks from evidence observed "
    "during an authorized scan of a verified target. Absence of findings does not prove "
    "absence of vulnerabilities."
)
AI_DISCLAIMER = (
    "AI-generated enrichment. Non-authoritative interpretation of the scanner findings "
    "above; it does not add, remove or confirm findings."
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _enum(value: Any) -> Any:
    return getattr(value, "value", value)


def _finding_sort_key(f: Finding) -> tuple:
    sev = _enum(f.severity)
    rank = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return (rank, f.plugin_id, f.fingerprint)


def build_report_document(
    scan: Scan,
    target: ScanTarget,
    findings: list[Finding],
    *,
    ai_enrichment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ordered = sorted(findings, key=_finding_sort_key)
    by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    for f in ordered:
        by_severity[_enum(f.severity)] = by_severity.get(_enum(f.severity), 0) + 1

    stats = scan.stats or {}
    document: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "orchestrasecai.scan_report",
        "scan": {
            "id": str(scan.id),
            "status": _enum(scan.status),
            "mission": scan.mission,
            "target": target.base_url,
            "verified_domain": target.verified_domain,
            "created_at": _iso(scan.created_at),
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
            "error_code": scan.error_code,
            "active_probes_enabled": bool(scan.active_probes_enabled),
        },
        "summary": {
            "total_findings": len(ordered),
            "by_severity": by_severity,
            "pages_crawled": stats.get("pages_crawled", 0),
            "agent_iterations": stats.get("agent_iterations", 0),
            "partial": _enum(scan.status) != "completed",
        },
        "findings": [
            {
                "id": str(f.id),
                "fingerprint": f.fingerprint,
                "plugin_id": f.plugin_id,
                "check_id": f.check_id,
                "check_version": f.check_version,
                "severity": _enum(f.severity),
                "status": _enum(f.status),
                "title": f.title,
                "description": f.description,
                "location": f.location or {},
                "remediation": f.remediation,
                "cvss_estimate": float(f.cvss_estimate) if f.cvss_estimate is not None else None,
                "evidence": [
                    {"type": e.evidence_type, "payload": e.payload or {}}
                    for e in sorted(f.evidence, key=lambda e: (e.evidence_type, str(e.id)))
                ],
            }
            for f in ordered
        ],
        "disclaimer": DISCLAIMER,
        "ai_enrichment": None,
    }
    if ai_enrichment:
        document["ai_enrichment"] = {"disclaimer": AI_DISCLAIMER, **ai_enrichment}
    return document


def render_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, default=str)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>OrchestraSecAI Report {{ doc.scan.id }}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#0f172a}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #e2e8f0;padding:6px;text-align:left;vertical-align:top}
th{background:#f1f5f9}.sev-high{color:#b91c1c}.sev-medium{color:#b45309}.sev-low{color:#1d4ed8}
.note{background:#fef3c7;padding:.75rem;border-radius:6px}.ai{background:#eef2ff;padding:.75rem;border-radius:6px}
pre{white-space:pre-wrap;word-break:break-word;background:#f8fafc;padding:.5rem;font-size:12px}
</style>
</head>
<body>
<h1>Security Scan Report</h1>
<p class="note">{{ doc.disclaimer }}</p>
<table>
<tr><th>Scan</th><td>{{ doc.scan.id }}</td></tr>
<tr><th>Target</th><td>{{ doc.scan.target }} (verified domain: {{ doc.scan.verified_domain }})</td></tr>
<tr><th>Status</th><td>{{ doc.scan.status }}{% if doc.summary.partial %} (partial results){% endif %}</td></tr>
<tr><th>Started / finished</th><td>{{ doc.scan.started_at }} / {{ doc.scan.finished_at }}</td></tr>
<tr><th>Active probes</th><td>{{ "enabled" if doc.scan.active_probes_enabled else "disabled" }}</td></tr>
<tr><th>Mission</th><td>{{ doc.scan.mission }}</td></tr>
</table>
<h2>Summary</h2>
<p>{{ doc.summary.total_findings }} findings:
{% for sev, n in doc.summary.by_severity.items() %}{{ sev }}={{ n }}{% if not loop.last %}, {% endif %}{% endfor %}.
Pages crawled: {{ doc.summary.pages_crawled }}.</p>
<h2>Findings</h2>
{% for f in doc.findings %}
<section>
<h3 class="sev-{{ f.severity }}">[{{ f.severity | upper }}] {{ f.title }}</h3>
<p>{{ f.description }}</p>
<p><strong>Check:</strong> {{ f.plugin_id }}{% if f.check_id %} via {{ f.check_id }} {{ f.check_version or "" }}{% endif %}
&middot; <strong>Fingerprint:</strong> {{ f.fingerprint }} &middot; <strong>Status:</strong> {{ f.status }}</p>
<p><strong>Affected:</strong> {{ f.location.get("url") or f.location.get("host") or "" }}</p>
{% if f.remediation %}<p><strong>Remediation:</strong> {{ f.remediation }}</p>{% endif %}
{% for e in f.evidence %}<pre>{{ e.type }}: {{ e.payload | tojson(indent=2) }}</pre>{% endfor %}
</section>
{% else %}
<p>No findings were produced.</p>
{% endfor %}
{% if doc.ai_enrichment %}
<h2>AI enrichment</h2>
<div class="ai"><p><em>{{ doc.ai_enrichment.disclaimer }}</em></p>
<pre>{{ doc.ai_enrichment.analyses | tojson(indent=2) }}</pre></div>
{% endif %}
</body>
</html>
"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
_template = _env.from_string(_HTML_TEMPLATE)


def render_html(document: dict[str, Any]) -> str:
    return _template.render(doc=document)


def sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


async def load_report_inputs(db: AsyncSession, scan: Scan) -> tuple[ScanTarget, list[Finding]]:
    target = await db.get(ScanTarget, scan.scan_target_id)
    if target is None or target.org_id != scan.org_id:
        raise ValueError("Scan target missing or not owned by the scan organization")
    r = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan.id, Finding.org_id == scan.org_id)
        .options(selectinload(Finding.evidence))
    )
    return target, list(r.scalars().all())


async def store_report(
    db: AsyncSession, scan: Scan, *, ai_enrichment: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Generate and persist new JSON + HTML report versions for ``scan``."""
    target, findings = await load_report_inputs(db, scan)
    document = build_report_document(scan, target, findings, ai_enrichment=ai_enrichment)
    generator = "deterministic+ai" if ai_enrichment else "deterministic"
    for fmt, content in (
        (ReportFormat.json, render_json(document)),
        (ReportFormat.html, render_html(document)),
    ):
        r = await db.execute(
            select(func.coalesce(func.max(Report.version), 0)).where(
                Report.scan_id == scan.id, Report.format == fmt
            )
        )
        db.add(
            Report(
                scan_id=scan.id,
                format=fmt,
                content=content,
                version=int(r.scalar_one()) + 1,
                generator=generator,
                content_sha256=sha256(content),
            )
        )
    await db.flush()
    return document
