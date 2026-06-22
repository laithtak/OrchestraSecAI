from _check_helpers import make_page, page_ctx

from orchestrasecai.checks.csp_quality_check import CspQualityCheck


async def test_unsafe_inline_on_script_src_is_high():
    page = make_page(
        headers={
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "object-src 'none'; base-uri 'self'"
            )
        }
    )
    findings = await CspQualityCheck().run(page_ctx(page))
    unsafe = [f for f in findings if f.plugin_id == "csp_quality.unsafe_directive"]
    assert len(unsafe) == 1
    assert unsafe[0].severity == "high"


async def test_wildcard_source_is_medium():
    page = make_page(
        headers={
            "Content-Security-Policy": (
                "default-src 'self'; script-src *; object-src 'none'; base-uri 'self'"
            )
        }
    )
    findings = await CspQualityCheck().run(page_ctx(page))
    wildcard = [f for f in findings if f.plugin_id == "csp_quality.wildcard_source"]
    assert len(wildcard) == 1
    assert wildcard[0].severity == "medium"


async def test_missing_key_directives_reported():
    page = make_page(headers={"Content-Security-Policy": "script-src 'self'"})
    findings = await CspQualityCheck().run(page_ctx(page))
    missing = {f.location["directive"] for f in findings if f.plugin_id == "csp_quality.missing_directive"}
    assert {"default-src", "object-src", "base-uri"} <= missing


async def test_no_csp_returns_empty():
    findings = await CspQualityCheck().run(page_ctx(make_page()))
    assert findings == []
