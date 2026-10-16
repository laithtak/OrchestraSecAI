import asyncio
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import httpx

from orchestrasecai.checks.base import PageContext
from orchestrasecai.scanner.crawler.robots import RobotsCache
from orchestrasecai.scanner.crawler.scope import (
    extract_links,
    is_blocked_path,
    normalize_url,
)
from orchestrasecai.security.egress import (
    DEFAULT_MAX_RESPONSE_BYTES,
    PASSIVE_METHODS,
    EgressDenied,
    EgressPolicy,
    RequestBudget,
    guarded_client,
)
from orchestrasecai.security.passive_http import assert_passive_method
from orchestrasecai.security.scope import target_scope
from orchestrasecai.security.ssrf import Resolver

MAX_BODY_CHARS = 50_000
MAX_FRONTIER = 5_000


@dataclass
class CrawlResult:
    pages: list[PageContext] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)


class RateLimiter:
    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / max(rps, 0.1)
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self.interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


class CrawlerEngine:
    def __init__(
        self,
        base_url: str,
        allowed_hosts: list[str],
        max_pages: int = 50,
        max_depth: int = 3,
        requests_per_second: float = 1.0,
        respect_robots: bool = True,
        user_agent: str = "OrchestraSecAI-Scanner/0.1",
        blocked_patterns: list[str] | None = None,
        *,
        resolver: Resolver | None = None,
        budget: RequestBudget | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        # Raises ScopeError for malformed targets before any network activity.
        self.scope = target_scope(base_url, allowed_hosts)
        self.base_url = normalize_url(self.scope.base_url)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self.blocked_patterns = blocked_patterns or []
        self.rate_limiter = RateLimiter(requests_per_second)
        self.robots_cache = RobotsCache()
        self._policy = EgressPolicy(
            scope=self.scope,
            allowed_methods=PASSIVE_METHODS,
            max_response_bytes=max_response_bytes,
            blocked_path_patterns=tuple(self.blocked_patterns),
        )
        self._resolver = resolver
        self._budget = budget
        self._transport = transport

    def _parse_cookies(self, set_cookie_headers: list[str]) -> list[dict]:
        cookies = []
        for header in set_cookie_headers:
            parts = header.split(";")
            name_val = parts[0].strip()
            if "=" not in name_val:
                continue
            name, value = name_val.split("=", 1)
            flags = {
                "secure": any("secure" in p.lower() for p in parts[1:]),
                "httponly": any("httponly" in p.lower() for p in parts[1:]),
                "samesite": any("samesite" in p.lower() for p in parts[1:]),
            }
            cookies.append({"name": name.strip(), "value": value.strip(), "flags": flags})
        return cookies

    async def crawl(
        self, cancel_check: Callable[[], Awaitable[bool]] | None = None
    ) -> CrawlResult:
        assert_passive_method("GET")
        result = CrawlResult()
        visited: set[str] = set()
        queue: deque[tuple[str, int, str | None]] = deque([(self.base_url, 0, None)])

        async with guarded_client(
            self._policy,
            user_agent=self.user_agent,
            resolver=self._resolver,
            budget=self._budget,
            inner=self._transport,
        ) as client:
            rp = None
            if self.respect_robots:
                rp = await self.robots_cache.fetch(client, self.base_url, self.user_agent)

            while queue and len(result.pages) < self.max_pages:
                if cancel_check and await cancel_check():
                    break
                url, depth, _parent = queue.popleft()
                url = normalize_url(url)
                if url in visited or depth > self.max_depth:
                    continue
                if not self.scope.contains(url):
                    continue
                if is_blocked_path(url, self.blocked_patterns):
                    continue
                if rp and not self.robots_cache.can_fetch(rp, self.user_agent, url):
                    continue

                visited.add(url)
                await self.rate_limiter.acquire()
                try:
                    resp = await client.get(url)
                except EgressDenied as exc:
                    result.denied.append(f"{url}: {exc.reason}")
                    if exc.reason == "budget_exhausted":
                        break
                    continue
                except httpx.HTTPError as exc:
                    result.errors.append(f"{url}: {type(exc).__name__}")
                    continue

                headers = dict(resp.headers)
                content_type = resp.headers.get("content-type", "")
                body = resp.text[:MAX_BODY_CHARS] if content_type.startswith("text") else ""
                set_cookies = resp.headers.get_list("set-cookie")
                page = PageContext(
                    url=url,
                    final_url=str(resp.url),
                    status_code=resp.status_code,
                    headers=headers,
                    cookies=self._parse_cookies(set_cookies),
                    body_snippet=body[:8000],
                    depth=depth,
                )
                result.pages.append(page)
                if "text/html" in content_type and depth < self.max_depth:
                    for link in extract_links(str(resp.url), body):
                        if len(queue) >= MAX_FRONTIER:
                            break
                        if link not in visited and self.scope.contains(link):
                            queue.append((link, depth + 1, url))

        return result
