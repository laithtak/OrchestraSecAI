from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.propagate import extract, inject, set_global_textmap
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from orchestrasecai.config import get_settings
from orchestrasecai.observability.context import get_context_dict, otel_attributes

_tracer_provider: TracerProvider | None = None
_fastapi_instrumented = False


def init_tracing(service_name: str) -> None:
    global _tracer_provider
    settings = get_settings()
    if not settings.otel_enabled:
        return
    if _tracer_provider is not None:
        return

    set_global_textmap(CompositePropagator([TraceContextTextMapPropagator()]))
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    if settings.otel_exporter_otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

            exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except ImportError:
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    _tracer_provider = provider


def instrument_fastapi(app) -> None:
    global _fastapi_instrumented
    settings = get_settings()
    if not settings.otel_enabled or _fastapi_instrumented:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        return
    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls="/metrics,/api/v1/health,/api/v1/ready",
    )
    _fastapi_instrumented = True


def inject_trace_carrier() -> dict[str, str]:
    carrier: dict[str, str] = {}
    inject(carrier)
    return carrier


def extract_trace_carrier(carrier: dict[str, str] | None) -> Context | None:
    if not carrier:
        return None
    return extract(carrier)


@contextmanager
def start_job_span(
    name: str,
    carrier: dict[str, str] | None = None,
    attributes: dict[str, Any] | None = None,
) -> Iterator[trace.Span]:
    settings = get_settings()
    if not settings.otel_enabled:
        yield trace.INVALID_SPAN
        return

    tracer = trace.get_tracer(__name__)
    parent_ctx = extract_trace_carrier(carrier)
    attrs = {**otel_attributes(), **(attributes or {})}
    with tracer.start_as_current_span(name, context=parent_ctx, attributes=attrs) as span:
        yield span


async def enqueue_with_context(pool, function_name: str, *args, **kwargs):
    """Enqueue ARQ job with trace carrier and request_id from current context."""
    ctx = get_context_dict()
    request_id = ctx.get("request_id")
    if request_id:
        kwargs.setdefault("request_id", request_id)
    kwargs.setdefault("otel_carrier", inject_trace_carrier())
    return await pool.enqueue_job(function_name, *args, **kwargs)
