from _check_helpers import make_page, page_ctx

from orchestrasecai.checks.open_redirect_check import OpenRedirectCheck


async def test_flags_url_like_redirect_param():
    page = make_page(url="https://example.com/login?next=https://evil.example/")
    findings = await OpenRedirectCheck().run(page_ctx(page))
    assert len(findings) == 1
    assert findings[0].plugin_id == "open_redirect.candidate_param"
    assert findings[0].severity == "low"
    assert findings[0].location["param"] == "next"


async def test_flags_path_like_value():
    page = make_page(url="https://example.com/go?redirect=/dashboard")
    findings = await OpenRedirectCheck().run(page_ctx(page))
    assert len(findings) == 1
    assert findings[0].location["param"] == "redirect"


async def test_ignores_non_url_value():
    page = make_page(url="https://example.com/go?next=hello")
    findings = await OpenRedirectCheck().run(page_ctx(page))
    assert findings == []


async def test_ignores_unrelated_param():
    page = make_page(url="https://example.com/go?id=https://evil.example/")
    findings = await OpenRedirectCheck().run(page_ctx(page))
    assert findings == []


async def test_no_query_returns_empty():
    findings = await OpenRedirectCheck().run(page_ctx(make_page()))
    assert findings == []
