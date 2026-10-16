from orchestrasecai.domain.services.agent_runner import run_agent_scan
from orchestrasecai.domain.services.reaper import reap_stale_scans
from orchestrasecai.observability.context import bind_context, clear_context
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.observability.metrics import arq_jobs_total
from orchestrasecai.observability.tracing import start_job_span

logger = get_logger(__name__)


async def run_agent_scan_task(
    ctx,
    scan_id: str,
    request_id: str | None = None,
    otel_carrier: dict | None = None,
) -> dict:
    """Execute one scan. Scan-level failures are persisted, not raised, so ARQ does not
    blindly re-run a scan; crash recovery is handled by leases and the reaper."""
    job_id = str(ctx.get("job_id", "unknown"))
    bind_context(scan_id=str(scan_id), request_id=request_id)
    logger.info("arq_job_started", task="run_agent_scan_task", job_id=job_id, scan_id=scan_id)
    try:
        with start_job_span(
            "run_agent_scan_task",
            carrier=otel_carrier,
            attributes={"scan_id": str(scan_id), "job_id": job_id},
        ):
            outcome = await run_agent_scan(str(scan_id), request_id=request_id, job_id=job_id)
        arq_jobs_total.labels(task="run_agent_scan_task", status="success").inc()
        logger.info(
            "arq_job_completed",
            task="run_agent_scan_task",
            job_id=job_id,
            scan_id=scan_id,
            outcome=outcome,
        )
        return {"scan_id": str(scan_id), "status": outcome}
    except Exception as exc:
        arq_jobs_total.labels(task="run_agent_scan_task", status="error").inc()
        logger.error(
            "arq_job_failed",
            task="run_agent_scan_task",
            job_id=job_id,
            scan_id=scan_id,
            error_type=type(exc).__name__,
        )
        raise
    finally:
        clear_context()


async def reap_stale_scans_task(ctx) -> dict:
    redis = ctx.get("redis")

    async def enqueue(scan_id: str, job_id: str) -> None:
        await redis.enqueue_job("run_agent_scan_task", scan_id, _job_id=job_id)

    result = await reap_stale_scans(enqueue=enqueue)
    if any(result.values()):
        logger.info("scan_reaper_run", **result)
    return result
