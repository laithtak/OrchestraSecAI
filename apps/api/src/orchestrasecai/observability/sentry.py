from __future__ import annotations

import sentry_sdk
from sentry_sdk.integrations.asyncio import AsyncioIntegration
from sentry_sdk.integrations.fastapi import FastApiIntegration

from orchestrasecai.config import get_settings
from orchestrasecai.observability.context import get_context_dict

_initialized = False


def _before_send(event, _hint):
    ctx = get_context_dict()
    tags = event.setdefault("tags", {})
    for key in ("request_id", "org_id", "scan_id"):
        value = ctx.get(key)
        if value:
            tags[key] = value
    return event


def init_sentry(service_name: str) -> None:
    global _initialized
    if _initialized:
        return

    settings = get_settings()
    if not settings.sentry_dsn:
        return

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment,
        integrations=[
            FastApiIntegration(transaction_style="endpoint"),
            AsyncioIntegration(),
        ],
        traces_sample_rate=0.1 if settings.otel_enabled else 0.0,
        before_send=_before_send,
    )
    sentry_sdk.set_tag("service", service_name)
    _initialized = True
