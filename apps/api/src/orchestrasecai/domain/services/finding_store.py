"""Persist scanner findings: deterministic, deduplicated and evidence-redacted.

Findings only ever originate from deterministic check output (``FindingDraft``); AI
output is never written here. Persistence is idempotent per (scan_id, fingerprint), so
job retries and repeated agent tool calls cannot duplicate findings.
"""

import hashlib
import json
import re

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.checks.base import FindingDraft
from orchestrasecai.domain.remediation import remediation_for
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.persistence.tables.core import Finding, FindingEvidence, Scan, Severity
from orchestrasecai.security.redaction import mask_secrets, redact_evidence

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16,64}$")
MAX_EVIDENCE_ITEMS = 10


def normalize_fingerprint(draft: FindingDraft) -> str:
    if _FINGERPRINT_RE.match(draft.fingerprint or ""):
        return draft.fingerprint
    material = json.dumps(
        {"plugin_id": draft.plugin_id, "location": draft.location}, sort_keys=True, default=str
    )
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def normalize_severity(value: str) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.medium


async def persist_findings(
    db: AsyncSession,
    scan: Scan,
    drafts: list[FindingDraft],
    seen: set[str],
    *,
    check_id: str | None = None,
    check_version: str | None = None,
) -> int:
    count = 0
    for draft in drafts:
        fingerprint = normalize_fingerprint(draft)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        severity = normalize_severity(draft.severity)
        result = await db.execute(
            pg_insert(Finding)
            .values(
                scan_id=scan.id,
                org_id=scan.org_id,
                plugin_id=draft.plugin_id[:100],
                severity=severity,
                title=mask_secrets(draft.title)[:500],
                description=mask_secrets(draft.description),
                fingerprint=fingerprint,
                location=redact_evidence(draft.location or {}),
                cvss_estimate=draft.cvss_estimate,
                remediation=draft.remediation or remediation_for(draft.plugin_id),
                check_id=check_id,
                check_version=check_version,
            )
            .on_conflict_do_nothing(constraint="uq_findings_scan_fingerprint")
            .returning(Finding.id)
        )
        finding_id = result.scalar_one_or_none()
        if finding_id is None:
            continue  # already persisted by an earlier attempt or tool call
        for ev in draft.evidence[:MAX_EVIDENCE_ITEMS]:
            db.add(
                FindingEvidence(
                    finding_id=finding_id,
                    evidence_type=str(ev.get("evidence_type", "http_response"))[:50],
                    payload=redact_evidence(ev.get("payload", {})),
                )
            )
        await db.flush()
        count += 1
        await publish_event(
            str(scan.id),
            "scan.finding_created",
            {
                "finding_id": str(finding_id),
                "plugin_id": draft.plugin_id,
                "severity": severity.value,
            },
        )
    return count
