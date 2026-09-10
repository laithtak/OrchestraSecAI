"""Mandatory gateway for all agent-driven network I/O."""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.agent.schemas import ToolResult
from orchestrasecai.checks.base import CheckContext, FindingDraft, PageContext
from orchestrasecai.domain.services.audit import write_audit_log
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.domain.services.finding_store import persist_findings
from orchestrasecai.persistence.tables.core import CrawlPage, Scan, ScanCheckRun, ScanPolicy, ScanTarget
from orchestrasecai.scanner.active.engine import ActiveProbeEngine, params_hash
from orchestrasecai.scanner.crawler.engine import CrawlerEngine
from orchestrasecai.scanner.crawler.scope import is_in_scope
from orchestrasecai.scanner.cve.nvd import CveLookupService
from orchestrasecai.scanner.poc.generator import PocGenerator
from orchestrasecai.scanner.runtime.executor import CheckExecutor
from orchestrasecai.scanner.runtime.registry import build_registry
from orchestrasecai.security.ssrf import SSRFError, validate_target_url


class ScanToolLayer:
    def __init__(
        self,
        db: AsyncSession,
        scan: Scan,
        target: ScanTarget,
        policy: ScanPolicy,
        seen_fingerprints: set[str],
        user_id: UUID | None = None,
    ) -> None:
        self.db = db
        self.scan = scan
        self.target = target
        self.policy = policy
        self.seen = seen_fingerprints
        self.user_id = user_id
        self._crawl_pages: list[PageContext] | None = None

    async def _audit(self, tool: str, metadata: dict[str, Any]) -> None:
        await write_audit_log(
            self.db,
            org_id=self.scan.org_id,
            user_id=self.user_id,
            action="agent.tool_call",
            resource_type="scan",
            resource_id=str(self.scan.id),
            metadata={"tool": tool, **metadata},
        )

    async def execute(self, tool: str, params: dict[str, Any]) -> ToolResult:
        start = time.perf_counter()
        try:
            if tool == "passive_crawl":
                result = await self._passive_crawl(params)
            elif tool == "run_check":
                result = await self._run_check(params)
            elif tool == "active_probe":
                result = await self._active_probe(params)
            elif tool == "lookup_cve":
                result = await self._lookup_cve(params)
            elif tool == "generate_poc":
                result = await self._generate_poc(params)
            else:
                return ToolResult(
                    tool=tool,
                    params=params,
                    success=False,
                    error=f"Unknown tool: {tool}",
                    duration_ms=int((time.perf_counter() - start) * 1000),
                )
            result.duration_ms = int((time.perf_counter() - start) * 1000)
            return result
        except Exception as exc:
            return ToolResult(
                tool=tool,
                params=params,
                success=False,
                error=str(exc),
                duration_ms=int((time.perf_counter() - start) * 1000),
            )

    async def _passive_crawl(self, params: dict[str, Any]) -> ToolResult:
        await self._audit("passive_crawl", {"target": self.target.base_url})

        async def cancel_check():
            await self.db.refresh(self.scan)
            from orchestrasecai.persistence.tables.core import ScanStatus

            return self.scan.status.value == ScanStatus.cancelled.value

        crawler = CrawlerEngine(
            base_url=self.target.base_url,
            allowed_hosts=self.target.allowed_hosts or [],
            max_pages=params.get("max_pages", self.policy.max_pages),
            max_depth=params.get("max_depth", self.policy.max_depth),
            requests_per_second=self.policy.requests_per_second,
            respect_robots=self.policy.respect_robots_txt,
            user_agent=self.policy.user_agent,
            blocked_patterns=self.policy.blocked_path_patterns,
        )
        crawl_result = await crawler.crawl(cancel_check=cancel_check)
        self._crawl_pages = crawl_result.pages

        for page in crawl_result.pages:
            self.db.add(
                CrawlPage(
                    scan_id=self.scan.id,
                    url=page.url,
                    final_url=page.final_url,
                    status_code=page.status_code,
                    content_type=page.headers.get("content-type"),
                    depth=page.depth,
                    headers=page.headers,
                    body_snippet=page.body_snippet[:2000] if page.body_snippet else None,
                )
            )
            await publish_event(
                str(self.scan.id),
                "crawl.page_fetched",
                {"url": page.url, "status_code": page.status_code},
            )
        await self.db.commit()
        self.scan.stats = {**(self.scan.stats or {}), "pages_crawled": len(crawl_result.pages)}
        await self.db.commit()

        return ToolResult(
            tool="passive_crawl",
            params=params,
            success=True,
            data={"pages_crawled": len(crawl_result.pages), "errors": crawl_result.errors},
        )

    async def _get_page_context(self, target_url: str) -> PageContext:
        if self._crawl_pages:
            for p in self._crawl_pages:
                if p.url == target_url or p.final_url == target_url:
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

        validate_target_url(target_url)
        if not is_in_scope(target_url, self.target.base_url, self.target.allowed_hosts or []):
            raise ValueError(f"URL out of scope: {target_url}")

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(
                target_url,
                headers={"User-Agent": self.policy.user_agent},
            )
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
        plugin_id = params.get("plugin_id", "")
        target_url = params.get("target_url", self.target.base_url)
        await self._audit("run_check", {"plugin_id": plugin_id, "url": target_url})

        registry = build_registry()
        check = registry.get(plugin_id)
        if not check:
            return ToolResult(
                tool="run_check",
                params=params,
                success=False,
                error=f"Unknown plugin: {plugin_id}",
            )

        page = await self._get_page_context(target_url)
        ctx_base = CheckContext(scan_id=str(self.scan.id), org_id=str(self.scan.org_id))
        executor = CheckExecutor(registry)
        drafts, metrics = await executor.run_page_checks([check], ctx_base, page)

        count = await persist_findings(self.db, self.scan, drafts, self.seen)
        for pid, m in metrics.items():
            self.db.add(
                ScanCheckRun(
                    scan_id=self.scan.id,
                    check_plugin_id=pid,
                    status=m["status"],
                    duration_ms=m["duration_ms"],
                    error=m["error"],
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
        technique = params.get("technique", "")
        url = params.get("url", self.target.base_url)
        probe_params = params.get("params", {})
        await self._audit(
            "active_probe",
            {
                "technique": technique,
                "url": url,
                "params_hash": params_hash(probe_params),
            },
        )

        engine = ActiveProbeEngine(
            base_url=self.target.base_url,
            allowed_hosts=self.target.allowed_hosts or [],
            requests_per_second=float(self.policy.requests_per_second),
            user_agent=self.policy.user_agent,
            blocked_patterns=self.policy.blocked_path_patterns,
        )
        probe = await engine.probe(technique, url, probe_params)
        return ToolResult(
            tool="active_probe",
            params=params,
            success=probe.success,
            data=probe.data,
            error=probe.error,
        )

    async def _lookup_cve(self, params: dict[str, Any]) -> ToolResult:
        cpe = params.get("cpe_string", "")
        await self._audit("lookup_cve", {"cpe_string": cpe})
        service = CveLookupService()
        data = await service.lookup_by_cpe(cpe)
        return ToolResult(tool="lookup_cve", params=params, success=True, data=data)

    async def _generate_poc(self, params: dict[str, Any]) -> ToolResult:
        finding_id = params.get("finding_id")
        if not finding_id:
            return ToolResult(
                tool="generate_poc",
                params=params,
                success=False,
                error="finding_id required",
            )
        await self._audit("generate_poc", {"finding_id": str(finding_id)})
        gen = PocGenerator()
        data = await gen.generate(self.db, UUID(str(finding_id)))
        await self.db.commit()
        return ToolResult(tool="generate_poc", params=params, success=True, data=data)
