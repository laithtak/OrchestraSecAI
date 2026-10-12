"""Mandatory gateway for all agent-driven network I/O.

The planner proposes tool calls; this layer decides deterministically whether each
call is permitted and executes it through controlled implementations:

* every call is audited, and denials are audited as ``agent.tool_denied``;
* cancellation / lease ownership is checked before every call;
* agent-supplied budgets are clamped to the scan policy (they can only shrink);
* all target traffic uses the scope-pinned egress transport with a per-scan budget;
* active probes run only when the scan was explicitly authorized for them;
* PoC drafts are generated only for findings of this scan and stored as AI output.
"""

from __future__ import annotations

import re
import time
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.agent.schemas import ToolResult
from orchestrasecai.checks.base import CheckContext, CheckPhase, PageContext
from orchestrasecai.config import get_settings
from orchestrasecai.domain.services.audit import write_audit_log
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.domain.services.finding_store import persist_findings
from orchestrasecai.domain.services.scan_control import ScanControl, ScanStopped
from orchestrasecai.persistence.tables.core import (
    CrawlPage,
    Finding,
    Scan,
    ScanCheckRun,
    ScanPolicy,
    ScanTarget,
)
from orchestrasecai.scanner.active.engine import ActiveProbeEngine, params_hash
from orchestrasecai.scanner.crawler.engine import CrawlerEngine
from orchestrasecai.scanner.cve.nvd import CveLookupService
from orchestrasecai.scanner.poc.generator import PocGenerator
from orchestrasecai.scanner.runtime.executor import CheckExecutor
from orchestrasecai.scanner.runtime.registry import build_registry
from orchestrasecai.security.egress import (
    PASSIVE_METHODS,
    EgressDenied,
    EgressPolicy,
    RequestBudget,
    guarded_client,
)
from orchestrasecai.security.redaction import redact_headers
from orchestrasecai.security.scope import ScopeError, target_scope
from orchestrasecai.security.ssrf import Resolver

_CPE_RE = re.compile(r"^cpe:2\.3:[aho](:[^:\s]{1,100}){10}$")
KNOWN_TOOLS = frozenset(
    {"passive_crawl", "run_check", "active_probe", "lookup_cve", "generate_poc"}
)


class ToolDenied(Exception):
    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _clamp(value: Any, lower: int, upper: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return upper
    return max(lower, min(number, upper))


class ScanToolLayer:
    def __init__(
        self,
        db: AsyncSession,
        scan: Scan,
        target: ScanTarget,
        policy: ScanPolicy,
        seen_fingerprints: set[str],
        user_id: UUID | None = None,
        *,
        control: ScanControl | None = None,
        allow_active: bool = False,
        budget: RequestBudget | None = None,
        resolver: Resolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        settings = get_settings()
        self.db = db
        self.scan = scan
        self.target = target
        self.policy = policy
        self.seen = seen_fingerprints
        self.user_id = user_id
        self.control = control
        self.allow_active = allow_active
        self.budget = budget or RequestBudget(settings.scan_max_requests)
        self.max_response_bytes = settings.scan_max_response_bytes
        self._resolver = resolver
        self._transport = transport
        self._crawl_pages: list[PageContext] | None = None

    async def _audit(self, tool: str, metadata: dict[str, Any], *, denied: bool = False) -> None:
        await write_audit_log(
            self.db,
            org_id=self.scan.org_id,
            user_id=self.user_id,
            action="agent.tool_denied" if denied else "agent.tool_call",
            resource_type="scan",
            resource_id=str(self.scan.id),
            metadata={"tool": tool, **metadata},
        )
        # Commit immediately so the audit record survives a later tool failure.
        await self.db.commit()

    async def execute(self, tool: str, params: dict[str, Any]) -> ToolResult:
        start = time.perf_counter()

        def elapsed() -> int:
            return int((time.perf_counter() - start) * 1000)

        if self.control is not None:
            await self.control.ensure_running()  # ScanStopped propagates and ends the run
        if not isinstance(params, dict):
            params = {}
        try:
            if tool not in KNOWN_TOOLS:
                raise ToolDenied("unknown_tool", f"Unknown tool: {tool}")
            handler = getattr(self, f"_{tool}")
            result = await handler(params)
            result.duration_ms = elapsed()
            return result
        except ScanStopped:
            raise
        except ToolDenied as exc:
            await self._audit(tool, {"reason": exc.reason}, denied=True)
            return ToolResult(
                tool=tool, params=params, success=False, error=str(exc), duration_ms=elapsed()
            )
        except EgressDenied as exc:
            await self._audit(tool, {"reason": exc.reason}, denied=True)
            return ToolResult(
                tool=tool,
                params=params,
                success=False,
                error=f"Egress denied: {exc.reason}",
                duration_ms=elapsed(),
            )
        except Exception as exc:  # noqa: BLE001 - a failing tool must not end the scan
            await self.db.rollback()
            return ToolResult(
                tool=tool,
                params=params,
                success=False,
                error=f"Tool failed: {type(exc).__name__}",
                duration_ms=elapsed(),
            )

    def _egress_policy(self) -> EgressPolicy:
        return EgressPolicy(
            scope=target_scope(self.target.base_url, list(self.target.allowed_hosts or [])),
            allowed_methods=PASSIVE_METHODS,
            max_response_bytes=self.max_response_bytes,
            blocked_path_patterns=tuple(self.policy.blocked_path_patterns or []),
        )

    async def _passive_crawl(self, params: dict[str, Any]) -> ToolResult:
        max_pages = _clamp(params.get("max_pages", self.policy.max_pages), 1, self.policy.max_pages)
        max_depth = _clamp(params.get("max_depth", self.policy.max_depth), 0, self.policy.max_depth)
        await self._audit(
            "passive_crawl",
            {"target": self.target.base_url, "max_pages": max_pages, "max_depth": max_depth},
        )

        async def cancel_check() -> bool:
            return self.control is not None and await self.control.is_stopped()

        crawler = CrawlerEngine(
            base_url=self.target.base_url,
            allowed_hosts=list(self.target.allowed_hosts or []),
            max_pages=max_pages,
            max_depth=max_depth,
            requests_per_second=float(self.policy.requests_per_second),
            respect_robots=self.policy.respect_robots_txt,
            user_agent=self.policy.user_agent,
            blocked_patterns=list(self.policy.blocked_path_patterns or []),
            resolver=self._resolver,
            budget=self.budget,
            transport=self._transport,
            max_response_bytes=self.max_response_bytes,
        )
        crawl_result = await crawler.crawl(cancel_check=cancel_check)
        self._crawl_pages = crawl_result.pages

        for page in crawl_result.pages:
            await self.db.execute(
                pg_insert(CrawlPage)
                .values(
                    scan_id=self.scan.id,
                    url=page.url,
                    final_url=page.final_url,
                    status_code=page.status_code,
                    content_type=(page.headers.get("content-type") or "")[:255] or None,
                    depth=page.depth,
                    headers=redact_headers(page.headers),
                    body_snippet=page.body_snippet[:2000] if page.body_snippet else None,
                )
                .on_conflict_do_nothing(constraint="uq_crawl_pages_scan_url")
            )
            await publish_event(
                str(self.scan.id),
                "crawl.page_fetched",
                {"url": page.url, "status_code": page.status_code},
            )
        if crawl_result.denied:
            await self._audit(
                "passive_crawl", {"egress_denials": crawl_result.denied[:20]}, denied=True
            )
        self.scan.stats = {
            **(self.scan.stats or {}),
            "pages_crawled": len(crawl_result.pages),
            "requests_used": self.budget.used,
        }
        await self.db.commit()

        if self.control is not None:
            await self.control.ensure_running()
        return ToolResult(
            tool="passive_crawl",
            params=params,
            success=bool(crawl_result.pages),
            data={
                "pages_crawled": len(crawl_result.pages),
                "errors": crawl_result.errors[:20],
                "denied": crawl_result.denied[:20],
            },
            error=None if crawl_result.pages else "No pages could be fetched within scope",
        )

    async def _get_page_context(self, target_url: str) -> PageContext:
        if self._crawl_pages:
            for p in self._crawl_pages:
                if target_url in (p.url, p.final_url):
                    return p

        r = await self.db.execute(
            select(CrawlPage).where(
                CrawlPage.scan_id == self.scan.id,
                CrawlPage.url == target_url,
            )
        )
        row = r.scalar_one_or_none()
        if row:
            return PageContext(
                url=row.url,
                final_url=row.final_url or row.url,
                status_code=row.status_code or 0,
                headers=row.headers or {},
                cookies=[],
                body_snippet=row.body_snippet or "",
                depth=row.depth,
            )

        policy = self._egress_policy()
        try:
            policy.scope.check(target_url)
        except ScopeError as exc:
            raise ToolDenied("out_of_scope", f"URL out of scope: {target_url}") from exc
        async with guarded_client(
            policy,
            user_agent=self.policy.user_agent,
            resolver=self._resolver,
            budget=self.budget,
            inner=self._transport,
        ) as client:
            resp = await client.get(target_url)
        return PageContext(
            url=target_url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            headers=dict(resp.headers),
            cookies=[],
            body_snippet=resp.text[:2000],
            depth=0,
        )

    async def _run_check(self, params: dict[str, Any]) -> ToolResult:
        plugin_id = str(params.get("plugin_id", ""))[:100]
        target_url = str(params.get("target_url") or self.target.base_url)
        await self._audit("run_check", {"plugin_id": plugin_id, "url": target_url[:500]})

        registry = build_registry()
        check = registry.get(plugin_id)
        if not check:
            return ToolResult(
                tool="run_check",
                params=params,
                success=False,
                error=f"Unknown plugin: {plugin_id}",
            )
        if check.phase != CheckPhase.PAGE:
            # HOST/SCAN checks open their own connections outside the egress boundary.
            raise ToolDenied("check_phase_not_allowed", f"Plugin {plugin_id} is not agent-runnable")

        page = await self._get_page_context(target_url)
        # scan_config is deliberately empty: checks that would contact third-party hosts
        # (enable_active_network_checks) stay disabled on the agent path.
        ctx_base = CheckContext(scan_id=str(self.scan.id), org_id=str(self.scan.org_id))
        executor = CheckExecutor(registry)
        drafts, metrics = await executor.run_page_checks([check], ctx_base, page)

        count = await persist_findings(
            self.db,
            self.scan,
            drafts,
            self.seen,
            check_id=check.plugin_id,
            check_version=getattr(check, "version", None),
        )
        for pid, m in metrics.items():
            self.db.add(
                ScanCheckRun(
                    scan_id=self.scan.id,
                    check_plugin_id=pid,
                    status=m["status"],
                    duration_ms=m["duration_ms"],
                    error=(m["error"] or "")[:500] or None,
                )
            )
        await self.db.commit()

        return ToolResult(
            tool="run_check",
            params=params,
            success=True,
            findings=drafts,
            data={"findings_count": count, "metrics": metrics},
        )

    async def _active_probe(self, params: dict[str, Any]) -> ToolResult:
        technique = str(params.get("technique", ""))[:64]
        url = str(params.get("url") or self.target.base_url)
        probe_params = params.get("params") if isinstance(params.get("params"), dict) else {}
        if not self.allow_active:
            raise ToolDenied(
                "active_probes_not_authorized",
                "Active probes are not authorized for this scan",
            )
        await self._audit(
            "active_probe",
            {"technique": technique, "url": url[:500], "params_hash": params_hash(probe_params)},
        )
        engine = ActiveProbeEngine(
            base_url=self.target.base_url,
            allowed_hosts=list(self.target.allowed_hosts or []),
            requests_per_second=float(self.policy.requests_per_second),
            user_agent=self.policy.user_agent,
            blocked_patterns=list(self.policy.blocked_path_patterns or []),
            resolver=self._resolver,
            budget=self.budget,
            transport=self._transport,
        )
        probe = await engine.probe(technique, url, probe_params)
        await self.db.commit()
        return ToolResult(
            tool="active_probe",
            params=params,
            success=probe.success,
            data=probe.data,
            error=probe.error,
        )

    async def _lookup_cve(self, params: dict[str, Any]) -> ToolResult:
        cpe = str(params.get("cpe_string", ""))
        if not _CPE_RE.match(cpe):
            raise ToolDenied("invalid_parameters", "cpe_string must be a CPE 2.3 identifier")
        await self._audit("lookup_cve", {"cpe_string": cpe})
        service = CveLookupService()
        data = await service.lookup_by_cpe(cpe)
        return ToolResult(tool="lookup_cve", params=params, success=True, data=data)

    async def _generate_poc(self, params: dict[str, Any]) -> ToolResult:
        try:
            finding_id = UUID(str(params.get("finding_id")))
        except ValueError as exc:
            raise ToolDenied("invalid_parameters", "finding_id must be a UUID") from exc
        # Tenant + scan scoping: the model may only reference findings of this scan.
        r = await self.db.execute(
            select(Finding.id).where(
                Finding.id == finding_id,
                Finding.scan_id == self.scan.id,
                Finding.org_id == self.scan.org_id,
            )
        )
        if r.scalar_one_or_none() is None:
            raise ToolDenied("finding_not_in_scan", "Finding not found in this scan")
        await self._audit("generate_poc", {"finding_id": str(finding_id)})
        data = await PocGenerator().generate(self.db, self.scan, finding_id)
        await self.db.commit()
        return ToolResult(tool="generate_poc", params=params, success=True, data=data)
