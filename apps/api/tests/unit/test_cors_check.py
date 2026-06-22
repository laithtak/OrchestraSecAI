from _check_helpers import make_page, page_ctx

from orchestrasecai.checks.cors_check import CorsCheck


async def test_wildcard_with_credentials_is_high():
    page = make_page(
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    findings = await CorsCheck().run(page_ctx(page))
    assert len(findings) == 1
    assert findings[0].plugin_id == "cors.wildcard_with_credentials"
    assert findings[0].severity == "high"


async def test_null_origin_is_medium():
    page = make_page(headers={"Access-Control-Allow-Origin": "null"})
    findings = await CorsCheck().run(page_ctx(page))
    assert len(findings) == 1
    assert findings[0].plugin_id == "cors.reflected_origin"
    assert findings[0].severity == "medium"


async def test_specific_origin_with_credentials_is_medium():
    page = make_page(
        headers={
            "Access-Control-Allow-Origin": "https://evil.example",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    findings = await CorsCheck().run(page_ctx(page))
    assert len(findings) == 1
    assert findings[0].plugin_id == "cors.reflected_origin"
    assert findings[0].severity == "medium"


async def test_bare_wildcard_is_low():
    page = make_page(headers={"Access-Control-Allow-Origin": "*"})
    findings = await CorsCheck().run(page_ctx(page))
    assert len(findings) == 1
    assert findings[0].plugin_id == "cors.wildcard_origin"
    assert findings[0].severity == "low"


async def test_no_acao_header_returns_empty():
    findings = await CorsCheck().run(page_ctx(make_page()))
    assert findings == []
