from __future__ import annotations

import logging
import sys

import structlog

from orchestrasecai.config import get_settings
from orchestrasecai.observability.context import CORRELATION_KEYS, get_context_dict

_configured = False


def _add_correlation_ids(
    _logger: logging.Logger,
    _method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    ctx = get_context_dict()
    for key in CORRELATION_KEYS:
        event_dict.setdefault(key, ctx.get(key))
    return event_dict


def configure_logging(service_name: str) -> None:
    global _configured
    if _configured:
        return

    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _add_correlation_ids,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    root = logging.getLogger()
    root.setLevel(log_level)

    structlog.contextvars.bind_contextvars(service=service_name)
    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
