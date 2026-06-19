import time

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, HostContext, PageContext
from orchestrasecai.scanner.runtime.registry import CheckRegistry


class CheckExecutor:
    def __init__(self, registry: CheckRegistry) -> None:
        self.registry = registry

    async def run_page_checks(
        self, checks: list, ctx_base: CheckContext, page: PageContext
    ) -> tuple[list[FindingDraft], dict[str, dict]]:
        ctx = CheckContext(
            scan_id=ctx_base.scan_id,
            org_id=ctx_base.org_id,
            page=page,
            scan_config=ctx_base.scan_config,
        )
        all_findings: list[FindingDraft] = []
        metrics: dict[str, dict] = {}
        page_checks = [c for c in checks if c.phase == CheckPhase.PAGE]
        for check in page_checks:
            start = time.perf_counter()
            try:
                findings = await check.run(ctx)
                all_findings.extend(findings)
                metrics[check.plugin_id] = {
                    "status": "completed",
                    "duration_ms": int((time.perf_counter() - start) * 1000),
                    "error": None,
                }
            except Exception as exc:
                metrics[check.plugin_id] = {
                    "status": "failed",
                    "duration_ms": int((time.perf_counter() - start) * 1000),
                    "error": str(exc),
                }
        return all_findings, metrics

    async def run_host_checks(
        self, checks: list, ctx_base: CheckContext, hostname: str
    ) -> tuple[list[FindingDraft], dict[str, dict]]:
        host = HostContext(hostname=hostname)
        ctx = CheckContext(
            scan_id=ctx_base.scan_id,
            org_id=ctx_base.org_id,
            host=host,
            scan_config=ctx_base.scan_config,
        )
        all_findings: list[FindingDraft] = []
        metrics: dict[str, dict] = {}
        host_checks = [c for c in checks if c.phase == CheckPhase.HOST]
        for check in host_checks:
            start = time.perf_counter()
            try:
                findings = await check.run(ctx)
                all_findings.extend(findings)
                metrics[check.plugin_id] = {
                    "status": "completed",
                    "duration_ms": int((time.perf_counter() - start) * 1000),
                    "error": None,
                }
            except Exception as exc:
                metrics[check.plugin_id] = {
                    "status": "failed",
                    "duration_ms": int((time.perf_counter() - start) * 1000),
                    "error": str(exc),
                }
        return all_findings, metrics
