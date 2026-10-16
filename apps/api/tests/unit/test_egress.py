"""Egress boundary: scope, SSRF, DNS rebinding, redirects, budgets, size caps."""

import httpx
import pytest

from orchestrasecai.security.egress import (
    EgressDenied,
    EgressPolicy,
    RequestBudget,
    guarded_client,
)
from orchestrasecai.security.scope import target_scope

PUBLIC_IP = "93.184.216.34"


def make_resolver(answers: dict[str, list[list[str]] | list[str]]):
    """Resolver returning successive answers per host (to simulate rebinding)."""
    calls: dict[str, int] = {}

    async def resolve(host: str, port: int) -> list[str]:
        value = answers.get(host)
        if value is None:
            raise OSError("NXDOMAIN")
        if value and isinstance(value[0], list):
            i = calls.get(host, 0)
            calls[host] = i + 1
            return value[min(i, len(value) - 1)]  # type: ignore[return-value]
        return value  # type: ignore[return-value]

    return resolve


def policy(base="https://app.example.com", hosts=None, **kw) -> EgressPolicy:
    return EgressPolicy(scope=target_scope(base, hosts or []), **kw)


def client_for(handler, pol=None, resolver=None, budget=None, **kw):
    return guarded_client(
        pol or policy(),
        user_agent="test-agent",
        resolver=resolver or make_resolver({"app.example.com": [PUBLIC_IP]}),
        budget=budget,
        inner=httpx.MockTransport(handler),
        **kw,
    )


@pytest.mark.asyncio
async def test_connection_is_pinned_to_validated_ip_with_sni_and_host_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        seen["sni"] = request.extensions.get("sni_hostname")
        seen["host_header"] = request.headers["host"]
        seen["accept_encoding"] = request.headers["accept-encoding"]
        return httpx.Response(200, text="ok")

    async with client_for(handler) as client:
        resp = await client.get("https://app.example.com/")
    assert resp.status_code == 200
    assert seen == {
        "host": PUBLIC_IP,
        "sni": "app.example.com",
        "host_header": "app.example.com",
        "accept_encoding": "identity",
    }
    # The caller still sees the hostname URL, not the pinned address.
    assert resp.url.host == "app.example.com"


@pytest.mark.asyncio
async def test_dns_rebinding_second_resolution_to_private_ip_is_blocked():
    resolver = make_resolver({"app.example.com": [[PUBLIC_IP], ["127.0.0.1"]]})
    async with client_for(lambda r: httpx.Response(200), resolver=resolver) as client:
        assert (await client.get("https://app.example.com/a")).status_code == 200
        with pytest.raises(EgressDenied) as exc:
            await client.get("https://app.example.com/b")
    assert exc.value.reason == "ssrf_blocked"


@pytest.mark.asyncio
async def test_mixed_public_and_private_answers_are_rejected():
    resolver = make_resolver({"app.example.com": [PUBLIC_IP, "10.0.0.5"]})
    async with client_for(lambda r: httpx.Response(200), resolver=resolver) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.get("https://app.example.com/")
    assert exc.value.reason == "ssrf_blocked"


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_host_is_blocked():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://evil.example.net/steal"})

    async with client_for(handler) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.get("https://app.example.com/")
    assert exc.value.reason == "out_of_scope"


@pytest.mark.asyncio
async def test_redirect_to_metadata_ip_literal_is_blocked():
    def handler(request):
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/"})

    async with client_for(handler) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.get("https://app.example.com/")
    assert exc.value.reason == "out_of_scope"


@pytest.mark.asyncio
async def test_redirect_to_in_scope_host_resolving_privately_is_blocked():
    pol = policy(hosts=["internal.app.example.com"])
    resolver = make_resolver(
        {"app.example.com": [PUBLIC_IP], "internal.app.example.com": ["192.168.1.10"]}
    )

    def handler(request):
        if request.extensions["sni_hostname"] == "app.example.com":
            return httpx.Response(302, headers={"Location": "https://internal.app.example.com/"})
        return httpx.Response(200)

    async with client_for(handler, pol=pol, resolver=resolver) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.get("https://app.example.com/")
    assert exc.value.reason == "ssrf_blocked"


@pytest.mark.asyncio
async def test_in_scope_redirect_is_followed():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(301, headers={"Location": "/login"})
        return httpx.Response(200, text="login")

    async with client_for(handler) as client:
        resp = await client.get("https://app.example.com/")
    assert resp.status_code == 200
    assert str(resp.url) == "https://app.example.com/login"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://app.example.com:8443/", "out_of_scope"),
        ("ftp://app.example.com/", "out_of_scope"),
        ("https://user:pw@app.example.com/", "out_of_scope"),
        ("https://other.example.com/", "out_of_scope"),
        ("https://example.com/", "out_of_scope"),
    ],
)
async def test_scope_violations_are_denied(url, reason):
    async with client_for(lambda r: httpx.Response(200)) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.get(url)
    assert exc.value.reason == reason


@pytest.mark.asyncio
async def test_mutating_method_denied_under_passive_policy():
    async with client_for(lambda r: httpx.Response(200)) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.post("https://app.example.com/", content=b"x")
    assert exc.value.reason == "method_not_allowed"


@pytest.mark.asyncio
async def test_blocked_path_pattern_is_denied():
    pol = policy(blocked_path_patterns=("/logout",))
    async with client_for(lambda r: httpx.Response(200), pol=pol) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.get("https://app.example.com/account/logout")
    assert exc.value.reason == "blocked_path"


@pytest.mark.asyncio
async def test_request_budget_is_enforced_across_redirect_hops():
    budget = RequestBudget(max_requests=2)

    def handler(request):
        n = int(request.url.path.strip("/") or 0)
        return httpx.Response(302, headers={"Location": f"/{n + 1}"})

    async with client_for(handler, budget=budget) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.get("https://app.example.com/")
    assert exc.value.reason == "budget_exhausted"
    assert budget.used == 2


@pytest.mark.asyncio
async def test_response_body_is_capped():
    pol = policy(max_response_bytes=1024)
    async with client_for(lambda r: httpx.Response(200, content=b"a" * 50_000), pol=pol) as client:
        resp = await client.get("https://app.example.com/")
    assert len(resp.content) == 1024


@pytest.mark.asyncio
async def test_unresolvable_host_is_denied():
    resolver = make_resolver({})
    async with client_for(lambda r: httpx.Response(200), resolver=resolver) as client:
        with pytest.raises(EgressDenied) as exc:
            await client.get("https://app.example.com/")
    assert exc.value.reason == "ssrf_blocked"


@pytest.mark.asyncio
async def test_deny_hook_receives_reason():
    denials = []
    async with guarded_client(
        policy(),
        user_agent="t",
        resolver=make_resolver({"app.example.com": [PUBLIC_IP]}),
        inner=httpx.MockTransport(lambda r: httpx.Response(200)),
        on_deny=lambda reason, msg: denials.append(reason),
    ) as client:
        with pytest.raises(EgressDenied):
            await client.get("https://other.example.org/")
    assert denials == ["out_of_scope"]
