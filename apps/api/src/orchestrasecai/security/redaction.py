"""Redaction and size-bounding for persisted scanner evidence.

Scan targets routinely return session cookies, tokens and keys. Evidence must explain a
finding, not archive secrets, so sensitive header values are removed, secret-shaped
strings are masked, and payloads are bounded before they are stored.
"""

from __future__ import annotations

import json
import re
from typing import Any

REDACTED = "[REDACTED]"
MAX_STRING_CHARS = 1000
MAX_LIST_ITEMS = 50
MAX_DEPTH = 6
MAX_PAYLOAD_BYTES = 16_384

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-amz-security-token",
        "www-authenticate",
    }
)
_SENSITIVE_KEY_RE = re.compile(
    r"(passw|secret|token|api[_-]?key|private[_-]?key|session|credential|authorization)",
    re.IGNORECASE,
)
_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),  # GitHub tokens
    re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{10,}\b"),  # Stripe
    re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"),  # Slack
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
_SAFE_KEYS = frozenset({"token_type", "token_hint", "evidence_type"})


def mask_secrets(value: str) -> str:
    masked = value
    for pattern in _SECRET_PATTERNS:
        masked = pattern.sub(lambda m: f"{m.group(0)[:6]}…{REDACTED}", masked)
    if len(masked) > MAX_STRING_CHARS:
        masked = masked[:MAX_STRING_CHARS] + "…[truncated]"
    return masked


def _redact_set_cookie(value: str) -> str:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0] if parts and parts[0] else ""
    return "; ".join([f"{name}={REDACTED}", *parts[1:]])[:MAX_STRING_CHARS]


def redact_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in (headers or {}).items():
        lower = str(key).lower()
        if lower == "set-cookie":
            out[key] = _redact_set_cookie(str(value))
        elif lower in SENSITIVE_HEADERS:
            out[key] = REDACTED
        else:
            out[key] = mask_secrets(str(value))
    return out


def _redact(value: Any, depth: int, key: str | None = None) -> Any:
    if depth > MAX_DEPTH:
        return "[truncated: depth]"
    if isinstance(value, dict):
        if key is not None and key.lower() == "headers":
            return redact_headers(value)
        out: dict[str, Any] = {}
        for k, v in list(value.items())[:MAX_LIST_ITEMS]:
            ks = str(k)
            if ks.lower() in SENSITIVE_HEADERS and isinstance(v, dict):
                # e.g. {"cookie": {"name": ..., "value": ..., "flags": ...}}: keep the
                # metadata that explains the finding, drop the secret value.
                out[ks] = {
                    str(k2): REDACTED if str(k2).lower() == "value" else _redact(v2, depth + 2, str(k2))
                    for k2, v2 in list(v.items())[:MAX_LIST_ITEMS]
                }
            elif ks.lower() in SENSITIVE_HEADERS:
                out[ks] = _redact_set_cookie(str(v)) if ks.lower() == "set-cookie" else REDACTED
            elif ks not in _SAFE_KEYS and _SENSITIVE_KEY_RE.search(ks) and not isinstance(
                v, (bool, int, float, type(None))
            ):
                out[ks] = REDACTED
            else:
                out[ks] = _redact(v, depth + 1, ks)
        return out
    if isinstance(value, (list, tuple)):
        items = [_redact(v, depth + 1) for v in list(value)[:MAX_LIST_ITEMS]]
        if len(value) > MAX_LIST_ITEMS:
            items.append(f"[truncated: {len(value) - MAX_LIST_ITEMS} more]")
        return items
    if isinstance(value, str):
        return mask_secrets(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return mask_secrets(str(value))


def redact_evidence(payload: Any) -> Any:
    """Return a redacted, size-bounded copy of an evidence payload."""
    redacted = _redact(payload, 0)
    encoded = json.dumps(redacted, default=str)
    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return {"truncated": True, "preview": encoded[: MAX_PAYLOAD_BYTES // 2]}
    return redacted
