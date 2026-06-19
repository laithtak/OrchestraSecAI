from orchestrasecai.ai.pipelines.report import run_full_ai_pipeline
from orchestrasecai.observability.context import bind_context, clear_context
from orchestrasecai.observability.logging import get_logger
from orchestrasecai.observability.metrics import arq_jobs_total
from orchestrasecai.observability.tracing import start_job_span

logger = get_logger(__name__)


async def run_ai_analysis_task(
    ctx,
    scan_id: str,
    request_id: str | None = None,
    otel_carrier: dict | None = None,
) -> dict:
    job_id = ctx.get("job_id", "unknown")
    bind_context(scan_id=scan_id, request_id=request_id)
    logger.info("arq_job_started", task="run_ai_analysis_task", job_id=job_id, scan_id=scan_id)
    try:
        with start_job_span(
            "run_ai_analysis_task",
            carrier=otel_carrier,
            attributes={"scan_id": scan_id, "job_id": job_id},
        ):
            await run_full_ai_pipeline(scan_id)
        arq_jobs_total.labels(task="run_ai_analysis_task", status="success").inc()
        logger.info("arq_job_completed", task="run_ai_analysis_task", job_id=job_id, scan_id=scan_id)
        return {"scan_id": scan_id, "status": "ai_complete"}
    except Exception as exc:
        arq_jobs_total.labels(task="run_ai_analysis_task", status="error").inc()
        logger.error(
            "arq_job_failed",
            task="run_ai_analysis_task",
            job_id=job_id,
            scan_id=scan_id,
            error=str(exc),
        )
        raise
    finally:
        clear_context()
