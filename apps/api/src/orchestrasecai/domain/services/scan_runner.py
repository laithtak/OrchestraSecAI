import json
import time
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from orchestrasecai.checks.base import CheckContext, FindingDraft
from orchestrasecai.config import get_settings
from orchestrasecai.observability.context import bind_context
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.observability.metrics import scan_duration_seconds
from orchestrasecai.observability.tracing import enqueue_with_context
from orchestrasecai.persistence.tables.core import (
    CrawlPage,
    Finding,
    FindingEvidence,
    Scan,
    ScanCheckRun,
    ScanPolicy,
    ScanStatus,
    ScanTarget,
    Severity,
)
from orchestrasecai.scanner.crawler.engine import CrawlerEngine
from orchestrasecai.scanner.runtime.executor import CheckExecutor
from orchestrasecai.scanner.runtime.registry import build_registry

settings = get_settings()
logger = get_logger(__name__)


async def publish_event(scan_id: str, event: str, data: dict) -> None:
    redis = Redis.from_url(settings.redis_url)
    channel = f"scan:{scan_id}:events"
    payload = {"event": event, **data}
    await redis.publish(channel, json.dumps(payload))
    await redis.aclose()


async def _persist_findings(
    db: AsyncSession, scan: Scan, drafts: list[FindingDraft], seen: set[str]
) -> int:
    count = 0
    for draft in drafts:
        if draft.fingerprint in seen:
            continue
        seen.add(draft.fingerprint)
        finding = Finding(
            scan_id=scan.id,
            org_id=scan.org_id,
            plugin_id=draft.plugin_id,
            severity=Severity(draft.severity) if draft.severity in Severity.__members__ else Severity.medium,
            title=draft.title,
            description=draft.description,
            fingerprint=draft.fingerprint,
            location=draft.location,
        )
        db.add(finding)
        await db.flush()
        for ev in draft.evidence:
            db.add(
                FindingEvidence(
                    finding_id=finding.id,
                    evidence_type=ev.get("evidence_type", "http_response"),
                    payload=ev.get("payload", {}),
                )
            )
        count += 1
        await publish_event(
            str(scan.id),
            "scan.finding_created",
            {"finding_id": str(finding.id), "plugin_id": draft.plugin_id, "severity": draft.severity},
        )
    return count


async def run_scan(scan_id: str, request_id: str | None = None) -> None:
    bind_context(scan_id=scan_id, request_id=request_id)
    scan_start = time.perf_counter()
    logger.info("scan_started", scan_id=scan_id)

    engine_db = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine_db, expire_on_commit=False)

    try:
        async with session_factory() as db:
            scan = await db.get(Scan, UUID(scan_id))
            if not scan:
                logger.warning("scan_not_found", scan_id=scan_id)
                return
            bind_context(org_id=str(scan.org_id))
            target = await db.get(ScanTarget, scan.scan_target_id)
            policy = await db.get(ScanPolicy, scan.scan_policy_id)
            if not target or not policy:
                scan.status = ScanStatus.failed
                scan.error_message = "Missing target or policy"
                await db.commit()
                logger.error("scan_failed", scan_id=scan_id, reason="missing_target_or_policy")
                return

            scan.status = ScanStatus.crawling
            scan.started_at = scan.started_at or __import__("datetime").datetime.now(
                __import__("datetime").UTC
            )
            await db.commit()
            await publish_event(scan_id, "scan.status_changed", {"status": "crawling"})
            logger.info("scan_status_changed", scan_id=scan_id, status="crawling")

            crawl_start = time.perf_counter()

            async def cancel_check():
                await db.refresh(scan)
                return scan.status == ScanStatus.cancelled

            crawler = CrawlerEngine(
                base_url=target.base_url,
                allowed_hosts=target.allowed_hosts or [],
                max_pages=policy.max_pages,
                max_depth=policy.max_depth,
                requests_per_second=policy.requests_per_second,
                respect_robots=policy.respect_robots_txt,
                user_agent=policy.user_agent,
                blocked_patterns=policy.blocked_path_patterns,
            )
            crawl_result = await crawler.crawl(cancel_check=cancel_check)
            scan_duration_seconds.labels(phase="crawl").observe(time.perf_counter() - crawl_start)

            for page in crawl_result.pages:
                db.add(
                    CrawlPage(
                        scan_id=scan.id,
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
                    scan_id,
                    "crawl.page_fetched",
                    {"url": page.url, "status_code": page.status_code},
                )
            scan.stats = {**(scan.stats or {}), "pages_crawled": len(crawl_result.pages)}
            await db.commit()

            scan.status = ScanStatus.scanning
            await db.commit()
            await publish_event(scan_id, "scan.status_changed", {"status": "scanning"})
            logger.info("scan_status_changed", scan_id=scan_id, status="scanning")

            checks_start = time.perf_counter()
            registry = build_registry()
            checks = registry.get_many(scan.plugin_ids or ["header", "cookie", "tls", "disclosure"])
            executor = CheckExecutor(registry)
            ctx_base = CheckContext(scan_id=scan_id, org_id=str(scan.org_id))
            seen_fps: set[str] = set()
            total_findings = 0

            for page in crawl_result.pages:
                drafts, metrics = await executor.run_page_checks(checks, ctx_base, page)
                total_findings += await _persist_findings(db, scan, drafts, seen_fps)
                for plugin_id, m in metrics.items():
                    db.add(
                        ScanCheckRun(
                            scan_id=scan.id,
                            check_plugin_id=plugin_id,
                            status=m["status"],
                            duration_ms=m["duration_ms"],
                            error=m["error"],
                        )
                    )
                await db.commit()

            from urllib.parse import urlparse

            host = urlparse(target.base_url).hostname or ""
            if host:
                host_ctx = CheckContext(scan_id=scan_id, org_id=str(scan.org_id))
                drafts, metrics = await executor.run_host_checks(checks, host_ctx, host)
                total_findings += await _persist_findings(db, scan, drafts, seen_fps)
                for plugin_id, m in metrics.items():
                    db.add(
                        ScanCheckRun(
                            scan_id=scan.id,
                            check_plugin_id=plugin_id,
                            status=m["status"],
                            duration_ms=m["duration_ms"],
                            error=m["error"],
                        )
                    )
                await db.commit()
            scan_duration_seconds.labels(phase="checks").observe(time.perf_counter() - checks_start)

            scan.stats = {**(scan.stats or {}), "findings_count": total_findings}
            scan.status = ScanStatus.analyzing
            await db.commit()
            await publish_event(scan_id, "scan.status_changed", {"status": "analyzing"})
            logger.info("scan_status_changed", scan_id=scan_id, status="analyzing")

            from arq import create_pool
            from arq.connections import RedisSettings

            pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
            await enqueue_with_context(
                pool,
                "run_ai_analysis_task",
                scan_id,
                request_id=request_id,
            )
            await pool.aclose()

        scan_duration_seconds.labels(phase="total").observe(time.perf_counter() - scan_start)
        logger.info("scan_completed", scan_id=scan_id)
    except Exception as exc:
        logger.error("scan_failed", scan_id=scan_id, error=str(exc))
        raise
    finally:
        await engine_db.dispose()
