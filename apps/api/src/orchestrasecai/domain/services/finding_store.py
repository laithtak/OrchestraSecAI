from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.checks.base import FindingDraft
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.persistence.tables.core import Finding, FindingEvidence, Scan, Severity


async def persist_findings(
    db: AsyncSession, scan: Scan, drafts: list[FindingDraft], seen: set[str]
) -> int:
    count = 0
    for draft in drafts:
        if draft.fingerprint in seen:
            continue
        seen.add(draft.fingerprint)
        finding = Finding(
            scan_id=scan.id,
            org_id=scan.org_id,
            plugin_id=draft.plugin_id,
            severity=Severity(draft.severity) if draft.severity in Severity.__members__ else Severity.medium,
            title=draft.title,
            description=draft.description,
            fingerprint=draft.fingerprint,
            location=draft.location,
        )
        db.add(finding)
        await db.flush()
        for ev in draft.evidence:
            db.add(
                FindingEvidence(
                    finding_id=finding.id,
                    evidence_type=ev.get("evidence_type", "http_response"),
                    payload=ev.get("payload", {}),
                )
            )
        count += 1
        await publish_event(
            str(scan.id),
            "scan.finding_created",
            {"finding_id": str(finding.id), "plugin_id": draft.plugin_id, "severity": draft.severity},
        )
    return count
