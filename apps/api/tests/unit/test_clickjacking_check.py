from _check_helpers import make_page, page_ctx

from orchestrasecai.checks.clickjacking_check import ClickjackingCheck


async def test_missing_protection_is_medium():
    findings = await ClickjackingCheck().run(page_ctx(make_page()))
    assert len(findings) == 1
    assert findings[0].plugin_id == "clickjacking.missing_protection"
    assert findings[0].severity == "medium"


async def test_permissive_frame_ancestors_is_medium():
    page = make_page(headers={"Content-Security-Policy": "frame-ancestors *"})
    findings = await ClickjackingCheck().run(page_ctx(page))
    ids = {f.plugin_id: f for f in findings}
    assert "clickjacking.permissive_frame_ancestors" in ids
    assert ids["clickjacking.permissive_frame_ancestors"].severity == "medium"


async def test_weak_x_frame_options_is_low():
    page = make_page(headers={"X-Frame-Options": "ALLOWALL"})
    findings = await ClickjackingCheck().run(page_ctx(page))
    assert len(findings) == 1
    assert findings[0].plugin_id == "clickjacking.weak_x_frame_options"
    assert findings[0].severity == "low"


async def test_valid_x_frame_options_no_findings():
    page = make_page(headers={"X-Frame-Options": "DENY"})
    findings = await ClickjackingCheck().run(page_ctx(page))
    assert findings == []


async def test_valid_frame_ancestors_no_findings():
    page = make_page(headers={"Content-Security-Policy": "frame-ancestors 'self'"})
    findings = await ClickjackingCheck().run(page_ctx(page))
    assert findings == []
