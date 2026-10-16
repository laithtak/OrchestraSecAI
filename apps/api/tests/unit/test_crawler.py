"""Crawler uses the guarded transport: scope, redirects, budgets, limits."""

import httpx
import pytest

from orchestrasecai.scanner.active.engine import ActiveProbeEngine
from orchestrasecai.scanner.crawler.engine import CrawlerEngine
from orchestrasecai.security.egress import RequestBudget

PUBLIC_IP = "93.184.216.34"


async def public_resolver(host, port):
    return [PUBLIC_IP]


def site(pages: dict[str, httpx.Response]):
    requests: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.extensions["sni_hostname"]
        requests.append((request.method, host, request.url.path))
        resp = pages.get(f"{host}{request.url.path}")
        return resp if resp is not None else httpx.Response(404)

    return handler, requests


def html(body: str, **headers) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html", **headers}, text=body)


def crawler(handler, **kw) -> CrawlerEngine:
    params = {
        "base_url": "https://app.example.com",
        "allowed_hosts": [],
        "max_pages": 10,
        "max_depth": 2,
        "requests_per_second": 1000,
        "respect_robots": False,
        "resolver": public_resolver,
        "transport": httpx.MockTransport(handler),
    }
    params.update(kw)
    return CrawlerEngine(**params)


@pytest.mark.asyncio
async def test_crawl_follows_in_scope_links_only():
    handler, requests = site(
        {
            "app.example.com/": html(
                '<a href="/about">a</a><a href="https://evil.example.net/x">x</a>'
                '<a href="https://www.example.com/">sibling</a>'
            ),
            "app.example.com/about": html("about"),
        }
    )
    result = await crawler(handler).crawl()
    assert [p.url for p in result.pages] == [
        "https://app.example.com/",
        "https://app.example.com/about",
    ]
    assert {host for _, host, _ in requests} == {"app.example.com"}
    assert all(method == "GET" for method, _, _ in requests)


@pytest.mark.asyncio
async def test_crawl_does_not_follow_redirect_out_of_scope():
    handler, requests = site(
        {
            "app.example.com/": html('<a href="/go">go</a>'),
            "app.example.com/go": httpx.Response(
                302, headers={"Location": "https://evil.example.net/"}
            ),
        }
    )
    result = await crawler(handler).crawl()
    assert [p.url for p in result.pages] == ["https://app.example.com/"]
    assert result.denied == ["https://app.example.com/go: out_of_scope"]
    assert ("GET", "evil.example.net", "/") not in requests


@pytest.mark.asyncio
async def test_crawl_blocks_base_host_resolving_to_private_address():
    async def private_resolver(host, port):
        return ["10.0.0.7"]

    handler, requests = site({"app.example.com/": html("x")})
    result = await crawler(handler, resolver=private_resolver).crawl()
    assert result.pages == []
    assert result.denied == ["https://app.example.com/: ssrf_blocked"]
    assert requests == []


@pytest.mark.asyncio
async def test_crawl_respects_max_pages_and_request_budget():
    links = "".join(f'<a href="/p{i}">p</a>' for i in range(20))
    pages = {"app.example.com/": html(links)}
    pages.update({f"app.example.com/p{i}": html("leaf") for i in range(20)})
    handler, _ = site(pages)

    result = await crawler(handler, max_pages=5).crawl()
    assert len(result.pages) == 5

    budget = RequestBudget(3)
    result = await crawler(handler, budget=budget).crawl()
    assert len(result.pages) == 3
    assert budget.used == 3


@pytest.mark.asyncio
async def test_crawl_honours_blocked_path_patterns_and_cancellation():
    handler, _requests = site(
        {"app.example.com/": html('<a href="/logout">x</a><a href="/ok">y</a>'),
         "app.example.com/ok": html("ok")}
    )
    result = await crawler(handler, blocked_patterns=["/logout"]).crawl()
    assert "https://app.example.com/logout" not in [p.url for p in result.pages]

    calls = {"n": 0}

    async def cancel_after_first():
        calls["n"] += 1
        return calls["n"] > 1

    result = await crawler(handler).crawl(cancel_check=cancel_after_first)
    assert len(result.pages) == 1


def probe_engine(handler):
    return ActiveProbeEngine(
        base_url="https://app.example.com",
        allowed_hosts=[],
        requests_per_second=1000,
        resolver=public_resolver,
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_active_probe_rejects_unknown_technique_and_out_of_scope():
    engine = probe_engine(lambda r: httpx.Response(200))
    assert (await engine.probe("rm_rf", "https://app.example.com/")).success is False
    result = await engine.probe("cors_origin_test", "https://evil.example.net/")
    assert result.success is False and "out of scope" in result.error


@pytest.mark.asyncio
async def test_csrf_probe_uses_fixed_body_and_ignores_model_supplied_body():
    seen = {}

    def handler(request):
        seen["method"] = request.method
        seen["body"] = request.content
        return httpx.Response(200, text="ok")

    engine = probe_engine(handler)
    result = await engine.probe(
        "csrf_form_probe", "https://app.example.com/form", {"body": "action=delete_all"}
    )
    assert result.success is True
    assert seen == {"method": "POST", "body": b"orchestrasec_probe=1"}


@pytest.mark.asyncio
async def test_active_probe_validates_model_parameters():
    engine = probe_engine(lambda r: httpx.Response(200, text=""))
    bad_marker = await engine.probe(
        "reflected_xss_check", "https://app.example.com/", {"marker": "<script>alert(1)</script>"}
    )
    assert bad_marker.success is False
    bad_origin = await engine.probe(
        "cors_origin_test", "https://app.example.com/", {"origin": "https://x\r\nSet-Cookie: a"}
    )
    assert bad_origin.success is False


@pytest.mark.asyncio
async def test_active_probe_does_not_follow_redirects_off_scope():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://evil.example.net/"})

    engine = probe_engine(handler)
    result = await engine.probe("open_redirect_follow", "https://app.example.com/login")
    assert result.success is True
    assert result.data["status_code"] == 302
