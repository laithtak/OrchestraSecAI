from _check_helpers import host_ctx

import orchestrasecai.checks.subdomain_enum_check as mod
from orchestrasecai.checks.subdomain_enum_check import SubdomainEnumCheck


class _FakeResponse:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, response, *args, **kwargs):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        return self._response


def _patch_client(monkeypatch, response):
    def factory(*args, **kwargs):
        return _FakeClient(response, *args, **kwargs)

    monkeypatch.setattr(mod.httpx, "AsyncClient", factory)
    monkeypatch.setattr(mod, "validate_target_url", lambda url: None)


async def test_returns_empty_when_flag_absent():
    findings = await SubdomainEnumCheck().run(host_ctx("example.com"))
    assert findings == []


async def test_returns_empty_when_flag_false():
    findings = await SubdomainEnumCheck().run(
        host_ctx("example.com", scan_config={"enable_active_network_checks": False})
    )
    assert findings == []


async def test_discovers_subdomains_when_enabled(monkeypatch):
    response = _FakeResponse(
        200,
        [
            {"name_value": "a.example.com\n*.example.com"},
            {"name_value": "b.example.com"},
            {"name_value": "other.org"},
        ],
    )
    _patch_client(monkeypatch, response)
    findings = await SubdomainEnumCheck().run(
        host_ctx("example.com", scan_config={"enable_active_network_checks": True})
    )
    assert len(findings) == 1
    assert findings[0].plugin_id == "subdomain_enum.discovered"
    assert findings[0].severity == "info"
    subs = set(findings[0].location["subdomains"])
    assert subs == {"a.example.com", "b.example.com", "example.com"}


async def test_fails_soft_on_non_200(monkeypatch):
    _patch_client(monkeypatch, _FakeResponse(500, []))
    findings = await SubdomainEnumCheck().run(
        host_ctx("example.com", scan_config={"enable_active_network_checks": True})
    )
    assert findings == []
