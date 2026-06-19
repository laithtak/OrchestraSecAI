from arq.connections import RedisSettings

from orchestrasecai.config import get_settings
from orchestrasecai.observability.logging import configure_logging, get_logger
from orchestrasecai.observability.sentry import init_sentry
from orchestrasecai.observability.tracing import init_tracing
from orchestrasecai.workers.tasks.ai import run_ai_analysis_task
from orchestrasecai.workers.tasks.scan import run_scan_task

settings = get_settings()
logger = get_logger(__name__)


async def on_startup(ctx):
    configure_logging(settings.otel_service_name_worker)
    init_sentry(settings.otel_service_name_worker)
    init_tracing(settings.otel_service_name_worker)
    logger.info("worker_started")


async def on_shutdown(ctx):
    logger.info("worker_shutdown")


async def on_job_start(ctx):
    job_id = ctx.get("job_id", "unknown")
    logger.info("arq_job_dispatch", job_id=job_id)


async def on_job_end(ctx):
    job_id = ctx.get("job_id", "unknown")
    logger.info("arq_job_finished", job_id=job_id)


class WorkerSettings:
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    functions = [run_scan_task, run_ai_analysis_task]
    max_jobs = settings.worker_concurrency
    job_timeout = settings.scan_global_timeout_seconds
    on_startup = on_startup
    on_shutdown = on_shutdown
    on_job_start = on_job_start
    on_job_end = on_job_end
