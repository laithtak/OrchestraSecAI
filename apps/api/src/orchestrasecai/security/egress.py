"""Guarded HTTP egress for every scanner request.

``GuardedTransport`` is installed on every httpx client the scanner uses (crawler,
on-demand page fetches, active probes). Because httpx sends each redirect hop through
the transport, the checks below apply to the initial request *and* every redirect:

* method allowlist (passive GET/HEAD unless an active technique widens it);
* scheme, exact host and port must be inside the target scope;
* a per-scan total request budget;
* DNS resolution with every answer required to be a public address;
* the connection is pinned to the validated address (TLS SNI and certificate
  verification still use the hostname), so a second DNS lookup by the HTTP stack
  cannot be used for DNS rebinding;
* the response body is capped at ``max_response_bytes``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field, replace

import httpx

from orchestrasecai.security.scope import ScopeError, TargetScope
from orchestrasecai.security.ssrf import Resolver, SSRFError, resolve_public_addresses

PASSIVE_METHODS = frozenset({"GET", "HEAD"})
DEFAULT_MAX_RESPONSE_BYTES = 1_000_000
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=10.0)


class EgressDenied(SSRFError):
    """A scanner request was refused by egress policy."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class RequestBudget:
    """Total outbound request budget shared by all tools within one scan."""

    def __init__(self, max_requests: int) -> None:
        self.max_requests = max_requests
        self.used = 0

    def consume(self) -> None:
        if self.used >= self.max_requests:
            raise EgressDenied("budget_exhausted", "Scan request budget exhausted")
        self.used += 1


@dataclass(frozen=True)
class EgressPolicy:
    scope: TargetScope
    allowed_methods: frozenset[str] = PASSIVE_METHODS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    blocked_path_patterns: tuple[str, ...] = field(default_factory=tuple)

    def with_methods(self, methods: frozenset[str]) -> EgressPolicy:
        return replace(self, allowed_methods=frozenset(m.upper() for m in methods))


DenyHook = Callable[[str, str], None]


class _CappedStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, limit: int) -> None:
        self._stream = stream
        self._limit = limit

    async def __aiter__(self) -> AsyncIterator[bytes]:
        received = 0
        async for chunk in self._stream:
            remaining = self._limit - received
            if remaining <= 0:
                break
            piece = chunk[:remaining]
            received += len(piece)
            yield piece

    async def aclose(self) -> None:
        await self._stream.aclose()


class GuardedTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        policy: EgressPolicy,
        *,
        resolver: Resolver | None = None,
        budget: RequestBudget | None = None,
        inner: httpx.AsyncBaseTransport | None = None,
        on_deny: DenyHook | None = None,
    ) -> None:
        self.policy = policy
        self._resolver = resolver
        self._budget = budget
        self._inner = inner or httpx.AsyncHTTPTransport(retries=0)
        self._on_deny = on_deny

    def _deny(self, reason: str, message: str) -> EgressDenied:
        if self._on_deny is not None:
            self._on_deny(reason, message)
        return EgressDenied(reason, message)

    def _check_path(self, url: httpx.URL) -> None:
        path = url.path.lower()
        for pattern in self.policy.blocked_path_patterns:
            if pattern and pattern.lower() in path:
                raise self._deny("blocked_path", "URL path blocked by scan policy")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        method = request.method.upper()
        if method not in self.policy.allowed_methods:
            raise self._deny("method_not_allowed", f"HTTP method {method} not allowed")
        try:
            host = self.policy.scope.check(str(request.url))
        except ScopeError as exc:
            raise self._deny("out_of_scope", str(exc)) from exc
        self._check_path(request.url)
        if self._budget is not None:
            try:
                self._budget.consume()
            except EgressDenied as exc:
                raise self._deny(exc.reason, str(exc)) from exc

        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        try:
            addresses = await resolve_public_addresses(host, port, self._resolver)
        except SSRFError as exc:
            raise self._deny("ssrf_blocked", str(exc)) from exc

        headers = httpx.Headers(request.headers)
        headers["Accept-Encoding"] = "identity"
        pinned = httpx.Request(
            method,
            request.url.copy_with(host=addresses[0]),
            headers=headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": host},
        )
        response = await self._inner.handle_async_request(pinned)
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_CappedStream(response.stream, self.policy.max_response_bytes),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def guarded_client(
    policy: EgressPolicy,
    *,
    user_agent: str,
    resolver: Resolver | None = None,
    budget: RequestBudget | None = None,
    inner: httpx.AsyncBaseTransport | None = None,
    follow_redirects: bool = True,
    on_deny: DenyHook | None = None,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> httpx.AsyncClient:
    """Build the only kind of httpx client scanner code may use for target traffic."""
    transport = GuardedTransport(
        policy, resolver=resolver, budget=budget, inner=inner, on_deny=on_deny
    )
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=follow_redirects,
        max_redirects=DEFAULT_MAX_REDIRECTS,
        timeout=timeout,
        headers={"User-Agent": user_agent},
        trust_env=False,
    )
