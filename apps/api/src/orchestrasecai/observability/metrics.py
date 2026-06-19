from __future__ import annotations

from prometheus_client import Counter, Histogram
from prometheus_fastapi_instrumentator import Instrumentator

rate_limit_exceeded_total = Counter(
    "rate_limit_exceeded_total",
    "Rate limit denials",
    ["limiter"],
)

arq_jobs_total = Counter(
    "arq_jobs_total",
    "ARQ job executions",
    ["task", "status"],
)

scan_duration_seconds = Histogram(
    "scan_duration_seconds",
    "Scan pipeline duration in seconds",
    ["phase"],
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800),
)

_mounted = False


def mount_metrics(app) -> None:
    global _mounted
    if _mounted:
        return

    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/metrics", "/api/v1/health", "/api/v1/ready"],
    ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
    _mounted = True
