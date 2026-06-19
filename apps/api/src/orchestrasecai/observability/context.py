from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any

from starlette.requests import Request

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_org_id: ContextVar[str | None] = ContextVar("org_id", default=None)
_scan_id: ContextVar[str | None] = ContextVar("scan_id", default=None)

CORRELATION_KEYS = ("request_id", "org_id", "scan_id")


def bind_context(
    *,
    request_id: str | None = None,
    org_id: str | None = None,
    scan_id: str | None = None,
) -> list[Token]:
    """Bind correlation IDs; returns tokens for optional reset."""
    tokens: list[Token] = []
    if request_id is not None:
        tokens.append(_request_id.set(request_id))
    if org_id is not None:
        tokens.append(_org_id.set(org_id))
    if scan_id is not None:
        tokens.append(_scan_id.set(scan_id))
    return tokens


def clear_context() -> None:
    for var in (_request_id, _org_id, _scan_id):
        try:
            var.set(None)
        except LookupError:
            pass


def get_context_dict() -> dict[str, str | None]:
    return {
        "request_id": _request_id.get(),
        "org_id": _org_id.get(),
        "scan_id": _scan_id.get(),
    }


def context_from_request(request: Request) -> dict[str, str | None]:
    request_id = getattr(request.state, "request_id", None)
    org_id = getattr(request.state, "org_id", None)
    scan_id = getattr(request.state, "scan_id", None)
    return {
        "request_id": request_id,
        "org_id": str(org_id) if org_id is not None else None,
        "scan_id": str(scan_id) if scan_id is not None else None,
    }


def bind_request_context(request: Request) -> list[Token]:
    ctx = context_from_request(request)
    return bind_context(**ctx)


def otel_attributes() -> dict[str, Any]:
    attrs: dict[str, Any] = {}
    for key, value in get_context_dict().items():
        if value is not None:
            attrs[key] = value
    return attrs
