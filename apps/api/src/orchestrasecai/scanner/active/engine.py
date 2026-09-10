"""Active probing engine — mutating HTTP methods allowed only here."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

import httpx

from orchestrasecai.scanner.crawler.engine import RateLimiter
from orchestrasecai.scanner.crawler.scope import is_blocked_path, is_in_scope
from orchestrasecai.security.ssrf import SSRFError, validate_target_url

TechniqueHandler = Callable[..., Awaitable[dict[str, Any]]]


@dataclass
class TechniqueSpec:
    name: str
    allowed_methods: frozenset[str]
    handler: TechniqueHandler


@dataclass
class ProbeResult:
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


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
  ) -> None:
      self.base_url = base_url
      self.allowed_hosts = allowed_hosts
      self.user_agent = user_agent
      self.blocked_patterns = blocked_patterns or []
      self.rate_limiter = RateLimiter(requests_per_second)
      if not ActiveProbeEngine.TECHNIQUES:
          self._register_defaults()

  @classmethod
  def _register_defaults(cls) -> None:
      cls.TECHNIQUES = {
          "cors_origin_test": TechniqueSpec(
              "cors_origin_test",
              frozenset({"GET", "OPTIONS"}),
              cls._cors_origin_test,
          ),
          "open_redirect_follow": TechniqueSpec(
              "open_redirect_follow",
              frozenset({"GET"}),
              cls._open_redirect_follow,
          ),
          "csrf_form_probe": TechniqueSpec(
              "csrf_form_probe",
              frozenset({"POST"}),
              cls._csrf_form_probe,
          ),
          "reflected_xss_check": TechniqueSpec(
              "reflected_xss_check",
              frozenset({"GET"}),
              cls._reflected_xss_check,
          ),
          "cookie_flags_probe": TechniqueSpec(
              "cookie_flags_probe",
              frozenset({"GET"}),
              cls._cookie_flags_probe,
          ),
      }

  def _validate_url(self, url: str) -> None:
      if not is_in_scope(url, self.base_url, self.allowed_hosts):
          raise ValueError(f"URL out of scope: {url}")
      if is_blocked_path(url, self.blocked_patterns):
          raise ValueError(f"URL path blocked by policy: {url}")
      validate_target_url(url)

  async def probe(self, technique: str, url: str, params: dict[str, Any] | None = None) -> ProbeResult:
      if technique not in self.TECHNIQUES:
          return ProbeResult(success=False, error=f"Unknown technique: {technique}")
      try:
          self._validate_url(url)
      except (SSRFError, ValueError) as exc:
          return ProbeResult(success=False, error=str(exc))

      spec = self.TECHNIQUES[technique]
      await self.rate_limiter.acquire()
      try:
          data = await spec.handler(self, url, params or {})
          return ProbeResult(success=True, data=data)
      except Exception as exc:
          return ProbeResult(success=False, error=str(exc))

  @staticmethod
  async def _cors_origin_test(engine: ActiveProbeEngine, url: str, params: dict) -> dict:
      origin = params.get("origin", "https://evil.example.com")
      async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
          resp = await client.get(
              url,
              headers={"Origin": origin, "User-Agent": engine.user_agent},
          )
          acao = resp.headers.get("access-control-allow-origin", "")
          acac = resp.headers.get("access-control-allow-credentials", "")
          return {
              "status_code": resp.status_code,
              "access_control_allow_origin": acao,
              "access_control_allow_credentials": acac,
              "reflects_origin": acao == origin,
          }

  @staticmethod
  async def _open_redirect_follow(engine: ActiveProbeEngine, url: str, params: dict) -> dict:
      param = params.get("param", "redirect")
      test_url = f"{url}{'&' if '?' in url else '?'}{param}=https://evil.example.com"
      async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
          resp = await client.get(test_url, headers={"User-Agent": engine.user_agent})
          location = resp.headers.get("location", "")
          return {
              "status_code": resp.status_code,
              "location": location,
              "redirects_external": "evil.example.com" in location,
          }

  @staticmethod
  async def _csrf_form_probe(engine: ActiveProbeEngine, url: str, params: dict) -> dict:
      async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
          resp = await client.post(
              url,
              headers={"User-Agent": engine.user_agent, "Content-Type": "application/x-www-form-urlencoded"},
              data=params.get("body", "test=probe"),
          )
          return {"status_code": resp.status_code, "body_snippet": resp.text[:500]}

  @staticmethod
  async def _reflected_xss_check(engine: ActiveProbeEngine, url: str, params: dict) -> dict:
      marker = params.get("marker", "orchestrasec_xss_test")
      sep = "&" if "?" in url else "?"
      test_url = f"{url}{sep}q={marker}"
      async with httpx.AsyncClient(timeout=15.0) as client:
          resp = await client.get(test_url, headers={"User-Agent": engine.user_agent})
          return {
              "status_code": resp.status_code,
              "reflected": marker in resp.text,
              "marker": marker,
          }

  @staticmethod
  async def _cookie_flags_probe(engine: ActiveProbeEngine, url: str, params: dict) -> dict:
      async with httpx.AsyncClient(timeout=15.0) as client:
          resp = await client.get(url, headers={"User-Agent": engine.user_agent})
          cookies = resp.headers.get_list("set-cookie")
          flags = []
          for c in cookies:
              flags.append({
                  "raw": c[:200],
                  "secure": "secure" in c.lower(),
                  "httponly": "httponly" in c.lower(),
                  "samesite": "samesite" in c.lower(),
              })
          return {"status_code": resp.status_code, "cookies": flags}


def params_hash(params: dict[str, Any]) -> str:
    raw = str(sorted(params.items())).encode()
    return hashlib.sha256(raw).hexdigest()[:16]
