"""Pure unit tests: state machine, redaction, remediation and report rendering."""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from orchestrasecai.domain.remediation import remediation_for
from orchestrasecai.domain.reporting import build_report_document, render_html, render_json
from orchestrasecai.domain.scan_lifecycle import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    IllegalTransition,
    assert_transition,
)
from orchestrasecai.persistence.tables.core import (
    Finding,
    FindingEvidence,
    FindingStatus,
    Scan,
    ScanStatus,
    ScanTarget,
    Severity,
)
from orchestrasecai.security.redaction import REDACTED, redact_evidence, redact_headers


def test_terminal_states_have_no_outgoing_transitions():
    for state in TERMINAL_STATES:
        assert state not in ALLOWED_TRANSITIONS
        for dst in ScanStatus:
            with pytest.raises(IllegalTransition):
                assert_transition(state, dst)


@pytest.mark.parametrize(
    ("src", "dst"),
    [
        (ScanStatus.queued, ScanStatus.completed),  # cannot complete without running
        (ScanStatus.queued, ScanStatus.timed_out),
        (ScanStatus.running, ScanStatus.queued),
    ],
)
def test_illegal_transitions(src, dst):
    with pytest.raises(IllegalTransition):
        assert_transition(src, dst)


def test_redaction_masks_secrets_but_keeps_explanatory_data():
    payload = {
        "headers": {"Set-Cookie": "sid=abc123; Secure", "X-Api-Key": "k", "Server": "nginx"},
        "cookie": {"name": "sid", "value": "abc123", "flags": {"secure": True}},
        "snippet": "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig AKIAABCDEFGHIJKLMNOP",
        "password": "hunter2",
        "count": 3,
    }
    out = redact_evidence(payload)
    assert out["headers"] == {"Set-Cookie": f"sid={REDACTED}; Secure", "X-Api-Key": REDACTED, "Server": "nginx"}
    assert out["cookie"] == {"name": "sid", "value": REDACTED, "flags": {"secure": True}}
    assert "eyJzdWIi" not in out["snippet"] and "AKIAABCDEFGHIJKLMNOP" not in out["snippet"]
    assert out["password"] == REDACTED and out["count"] == 3
    assert "abc123" not in json.dumps(out)


def test_redaction_bounds_payload_size():
    out = redact_evidence({"blob": ["x" * 900] * 200})
    assert len(json.dumps(out)) < 20_000
    assert redact_headers({"Authorization": "Basic Zm9vOmJhcg=="}) == {"Authorization": REDACTED}


def test_remediation_lookup_prefers_specific_ids():
    assert "Strict-Transport-Security" in remediation_for("header.missing_strict_transport_security")
    assert "HttpOnly" in remediation_for("cookie.missing_httponly")
    assert remediation_for("unknown.plugin") is None


def _report_inputs(title: str):
    org = uuid4()
    target = ScanTarget(
        id=uuid4(), org_id=org, project_id=uuid4(), base_url="https://app.example.com/",
        verified_domain="app.example.com",
    )
    ts = datetime(2026, 10, 12, tzinfo=UTC)
    scan = Scan(
        id=uuid4(), org_id=org, scan_target_id=target.id, scan_policy_id=uuid4(),
        mission="<b>mission</b>", status=ScanStatus.completed, created_at=ts, started_at=ts,
        finished_at=ts, stats={"pages_crawled": 2}, active_probes_enabled=False,
    )
    findings = []
    for sev, fp in [(Severity.low, "b" * 32), (Severity.high, "a" * 32), (Severity.medium, "c" * 32)]:
        f = Finding(
            id=uuid4(), scan_id=scan.id, org_id=org, plugin_id="disclosure.debug_header",
            severity=sev, title=title, description="desc <img src=x onerror=alert(1)>",
            fingerprint=fp, location={"url": "https://app.example.com/"},
            status=FindingStatus.open, remediation="fix it",
        )
        f.evidence = [FindingEvidence(id=uuid4(), evidence_type="http_response",
                                      payload={"snippet": "</pre><script>alert(2)</script>"})]
        findings.append(f)
    return scan, target, findings


def test_report_is_deterministic_and_ordered_by_severity():
    scan, target, findings = _report_inputs("Debug header")
    doc1 = build_report_document(scan, target, findings)
    doc2 = build_report_document(scan, target, list(reversed(findings)))
    assert render_json(doc1) == render_json(doc2)
    assert [f["severity"] for f in doc1["findings"]] == ["high", "medium", "low"]
    assert doc1["summary"]["by_severity"] == {"high": 1, "medium": 1, "low": 1, "info": 0}
    assert doc1["ai_enrichment"] is None


def test_html_report_escapes_target_and_ai_content():
    scan, target, findings = _report_inputs("<script>alert('title')</script>")
    doc = build_report_document(
        scan, target, findings,
        ai_enrichment={"model": "m", "analyses": {"executive_summary": {"text": "<script>x</script>"}}},
    )
    html = render_html(doc)
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "&lt;script&gt;" in html
    assert "Non-authoritative" in html
