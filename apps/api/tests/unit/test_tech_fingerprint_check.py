from _check_helpers import make_page, page_ctx

from orchestrasecai.checks.tech_fingerprint_check import TechFingerprintCheck


async def test_detects_header_meta_body_and_cookie_signals():
    page = make_page(
        headers={"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2.0"},
        cookies=[{"name": "PHPSESSID", "value": "abc"}],
        body_snippet='<meta name="generator" content="WordPress 6.4"> __NEXT_DATA__',
    )
    findings = await TechFingerprintCheck().run(page_ctx(page))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.plugin_id == "tech_fingerprint.detected"
    assert finding.severity == "info"
    names = {t["name"] for t in finding.location["technologies"]}
    assert "nginx" in names
    assert "Next.js" in names


async def test_no_signals_returns_empty():
    findings = await TechFingerprintCheck().run(page_ctx(make_page()))
    assert findings == []
