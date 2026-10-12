"""Active probing engine — non-GET methods are allowed only here.

Each technique is explicitly named, uses fixed request shapes, validates every
model-supplied parameter against a strict pattern, and sends traffic only through a
``GuardedTransport`` restricted to that technique's methods. Whether active probing is
permitted at all for a scan is decided by ``ScanToolLayer`` before this engine runs.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from orchestrasecai.scanner.crawler.engine import RateLimiter
from orchestrasecai.scanner.crawler.scope import is_blocked_path
from orchestrasecai.security.egress import (
    EgressDenied,
    EgressPolicy,
    RequestBudget,
    guarded_client,
)
from orchestrasecai.security.scope import ScopeError, target_scope
from orchestrasecai.security.ssrf import Resolver

TechniqueHandler = Callable[..., Awaitable[dict[str, Any]]]

PROBE_ORIGIN = "https://orchestrasec-cors-probe.invalid"
REDIRECT_PROBE_TARGET = "https://orchestrasec-redirect-probe.invalid/"
_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
_MARKER_RE = re.compile(r"^[A-Za-z0-9_]{6,40}$")
_ORIGIN_RE = re.compile(r"^https?://[a-z0-9.-]{1,100}(:\d{1,5})?$")


class ProbeParamError(ValueError):
    """A model-supplied probe parameter failed validation."""


@dataclass
class TechniqueSpec:
    name: str
    allowed_methods: frozenset[str]
    handler: TechniqueHandler
    mutating: bool = False


@dataclass
class ProbeResult:
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _param_name(params: dict, key: str, default: str) -> str:
    value = str(params.get(key, default))
    if not _PARAM_NAME_RE.match(value):
        raise ProbeParamError(f"Invalid parameter name for '{key}'")
    return value


class ActiveProbeEngine:
    """Executes allowlisted active probe techniques with scope validation."""

    TECHNIQUES: dict[str, TechniqueSpec] = {}

    def __init__(
        self,
        base_url: str,
        allowed_hosts: list[str],
        requests_per_second: float = 2.0,
        user_agent: str = "OrchestraSecAI-Scanner/0.1",
        blocked_patterns: list[str] | None = None,
        *,
        resolver: Resolver | None = None,
        budget: RequestBudget | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url
        self.allowed_hosts = allowed_hosts
        self.user_agent = user_agent
        self.blocked_patterns = blocked_patterns or []
        self.rate_limiter = RateLimiter(requests_per_second)
        self.scope = target_scope(base_url, allowed_hosts)
        self._resolver = resolver
        self._budget = budget
        self._transport = transport
        if not ActiveProbeEngine.TECHNIQUES:
            self._register_defaults()

    @classmethod
    def _register_defaults(cls) -> None:
        cls.TECHNIQUES = {
            "cors_origin_test": TechniqueSpec(
                "cors_origin_test", frozenset({"GET"}), cls._cors_origin_test
            ),
            "open_redirect_follow": TechniqueSpec(
                "open_redirect_follow", frozenset({"GET"}), cls._open_redirect_follow
            ),
            "csrf_form_probe": TechniqueSpec(
                "csrf_form_probe", frozenset({"POST"}), cls._csrf_form_probe, mutating=True
            ),
            "reflected_xss_check": TechniqueSpec(
                "reflected_xss_check", frozenset({"GET"}), cls._reflected_xss_check
            ),
            "cookie_flags_probe": TechniqueSpec(
                "cookie_flags_probe", frozenset({"GET"}), cls._cookie_flags_probe
            ),
        }

    def _validate_url(self, url: str) -> None:
        try:
            self.scope.check(url)
        except ScopeError as exc:
            raise ValueError(f"URL out of scope: {url}") from exc
        if is_blocked_path(url, self.blocked_patterns):
            raise ValueError(f"URL path blocked by policy: {url}")

    def _client(self, spec: TechniqueSpec) -> httpx.AsyncClient:
        policy = EgressPolicy(
            scope=self.scope,
            blocked_path_patterns=tuple(self.blocked_patterns),
            max_response_bytes=200_000,
        ).with_methods(spec.allowed_methods)
        return guarded_client(
            policy,
            user_agent=self.user_agent,
            resolver=self._resolver,
            budget=self._budget,
            inner=self._transport,
            follow_redirects=False,
        )

    async def probe(
        self, technique: str, url: str, params: dict[str, Any] | None = None
    ) -> ProbeResult:
        spec = self.TECHNIQUES.get(technique)
        if spec is None:
            return ProbeResult(success=False, error=f"Unknown technique: {technique}")
        try:
            self._validate_url(url)
        except ValueError as exc:
            return ProbeResult(success=False, error=str(exc))

        await self.rate_limiter.acquire()
        try:
            async with self._client(spec) as client:
                data = await spec.handler(client, url, params or {})
            return ProbeResult(success=True, data=data)
        except ProbeParamError as exc:
            return ProbeResult(success=False, error=str(exc))
        except EgressDenied as exc:
            return ProbeResult(success=False, error=f"Egress denied: {exc.reason}")
        except httpx.HTTPError as exc:
            return ProbeResult(success=False, error=f"HTTP error: {type(exc).__name__}")

    @staticmethod
    async def _cors_origin_test(client: httpx.AsyncClient, url: str, params: dict) -> dict:
        origin = str(params.get("origin", PROBE_ORIGIN)).lower()
        if not _ORIGIN_RE.match(origin):
            raise ProbeParamError("Invalid origin")
        resp = await client.get(url, headers={"Origin": origin})
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        return {
            "status_code": resp.status_code,
            "access_control_allow_origin": acao[:200],
            "access_control_allow_credentials": acac[:20],
            "reflects_origin": acao == origin,
        }

    @staticmethod
    async def _open_redirect_follow(client: httpx.AsyncClient, url: str, params: dict) -> dict:
        param = _param_name(params, "param", "redirect")
        request = client.build_request("GET", url)
        test_url = request.url.copy_merge_params({param: REDIRECT_PROBE_TARGET})
        resp = await client.get(test_url)
        location = resp.headers.get("location", "")
        return {
            "status_code": resp.status_code,
            "location": location[:300],
            "redirects_external": location.startswith(REDIRECT_PROBE_TARGET.rstrip("/")),
        }

    @staticmethod
    async def _csrf_form_probe(client: httpx.AsyncClient, url: str, params: dict) -> dict:
        # Fixed, inert body: the model cannot choose what is submitted.
        resp = await client.post(
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            content=b"orchestrasec_probe=1",
        )
        return {"status_code": resp.status_code, "body_length": len(resp.content)}

    @staticmethod
    async def _reflected_xss_check(client: httpx.AsyncClient, url: str, params: dict) -> dict:
        marker = str(params.get("marker", "orchestrasec_xss_test"))
        if not _MARKER_RE.match(marker):
            raise ProbeParamError("Invalid marker")
        param = _param_name(params, "param", "q")
        request = client.build_request("GET", url)
        resp = await client.get(request.url.copy_merge_params({param: marker}))
        return {
            "status_code": resp.status_code,
            "reflected": marker in resp.text,
            "marker": marker,
            "param": param,
        }

    @staticmethod
    async def _cookie_flags_probe(client: httpx.AsyncClient, url: str, params: dict) -> dict:
        resp = await client.get(url)
        flags = []
        for c in resp.headers.get_list("set-cookie")[:20]:
            name = c.split("=", 1)[0].strip()[:100]
            lower = c.lower()
            flags.append(
                {
                    "name": name,
                    "secure": "secure" in lower,
                    "httponly": "httponly" in lower,
                    "samesite": "samesite" in lower,
                }
            )
        return {"status_code": resp.status_code, "cookies": flags}


def params_hash(params: dict[str, Any]) -> str:
    raw = json.dumps(params, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:16]
