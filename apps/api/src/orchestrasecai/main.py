from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from orchestrasecai.api.middleware.access_log import AccessLogMiddleware
from orchestrasecai.api.middleware.audit import AuditMiddleware
from orchestrasecai.api.middleware.rate_limit import RateLimitMiddleware, register_rate_limit_scripts
from orchestrasecai.api.middleware.request_id import RequestIdMiddleware
from orchestrasecai.api.v1.router import api_router
from orchestrasecai.config import get_settings
from orchestrasecai.observability.logging import configure_logging
from orchestrasecai.observability.metrics import mount_metrics
from orchestrasecai.observability.sentry import init_sentry
from orchestrasecai.observability.tracing import init_tracing, instrument_fastapi
from orchestrasecai.persistence.seed import run_seed
from orchestrasecai.scanner.runtime.registry import build_registry

_settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(_settings.otel_service_name_api)
    init_sentry(_settings.otel_service_name_api)
    init_tracing(_settings.otel_service_name_api)

    build_registry()
    await run_seed()
    app.state.redis = Redis.from_url(
        _settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
    )
    app.state.rate_limit_scripts = await register_rate_limit_scripts(app.state.redis)
    try:
        yield
    finally:
        await app.state.redis.aclose()


app = FastAPI(
    title="OrchestraSecAI API",
    version="0.1.0",
    lifespan=lifespan,
    openapi_url="/api/v1/openapi.json",
)

instrument_fastapi(app)
mount_metrics(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(AccessLogMiddleware)
app.include_router(api_router)


@app.exception_handler(Exception)
async def problem_handler(request: Request, exc: Exception):
    if hasattr(exc, "status_code"):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "type": "about:blank",
                "title": getattr(exc, "detail", str(exc)),
                "status": exc.status_code,
            },
            media_type="application/problem+json",
        )
    raise exc
