import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _redact(token: str) -> str:
    if len(token) <= 12:
        return "***"
    return f"{token[:6]}...{token[-4:]}"


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


class JWTCheck(SecurityCheck):
    plugin_id = "jwt"
    name = "JWT Inspection Check"
    phase = CheckPhase.PAGE
    aliases = ["jwt"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page:
            return []
        findings: list[FindingDraft] = []
        seen: set[str] = set()

        for source, raw in self._candidate_sources(ctx):
            for token in JWT_PATTERN.findall(raw or ""):
                if token in seen:
                    continue
                seen.add(token)
                decoded = _decode_jwt(token)
                if decoded is None:
                    continue
                header, payload = decoded
                findings.extend(self._analyze(ctx.page.url, source, token, header, payload))
        return findings

    def _candidate_sources(self, ctx: CheckContext) -> list[tuple[str, str]]:
        page = ctx.page
        assert page is not None
        sources: list[tuple[str, str]] = [("body", page.body_snippet or "")]
        auth = next(
            (v for k, v in page.headers.items() if k.lower() == "authorization"),
            None,
        )
        if auth:
            sources.append(("authorization_header", auth))
        for cookie in page.cookies:
            value = cookie.get("value") or ""
            if value:
                sources.append(("cookie", value))
        return sources

    def _analyze(
        self,
        url: str,
        source: str,
        token: str,
        header: dict[str, Any],
        payload: dict[str, Any],
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        alg = str(header.get("alg", "")).strip()
        redacted = _redact(token)
        location = {"url": url, "source": source, "alg": alg or None}
        evidence = [
            {
                "evidence_type": "jwt_inspection",
                "payload": {
                    "token": redacted,
                    "header": header,
                    "alg": alg or None,
                    "source": source,
                },
            }
        ]

        if alg.lower() == "none":
            fp = hashlib.sha256(f"jwt.alg_none:{url}:{redacted}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="jwt.alg_none",
                    severity="high",
                    title="JWT uses 'none' algorithm",
                    description=(
                        f"A JWT found via {source} declares alg:none, meaning the token is "
                        "unsigned and can be forged."
                    ),
                    fingerprint=fp,
                    location=location,
                    evidence=evidence,
                )
            )
        elif alg.upper().startswith("HS"):
            fp = hashlib.sha256(f"jwt.symmetric_alg:{url}:{redacted}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="jwt.symmetric_alg",
                    severity="info",
                    title=f"JWT uses symmetric algorithm {alg}",
                    description=(
                        f"A JWT found via {source} uses {alg}; verify the signing secret is "
                        "strong and not shared with clients."
                    ),
                    fingerprint=fp,
                    location=location,
                    evidence=evidence,
                )
            )

        exp = payload.get("exp")
        if exp is None:
            fp = hashlib.sha256(f"jwt.missing_exp:{url}:{redacted}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="jwt.missing_exp",
                    severity="medium",
                    title="JWT missing expiration claim",
                    description=(
                        f"A JWT found via {source} has no 'exp' claim and may never expire."
                    ),
                    fingerprint=fp,
                    location=location,
                    evidence=evidence,
                )
            )
        else:
            expired = False
            try:
                expired = datetime.fromtimestamp(float(exp), UTC) < datetime.now(UTC)
            except (TypeError, ValueError, OverflowError, OSError):
                expired = False
            if expired:
                fp = hashlib.sha256(f"jwt.expired:{url}:{redacted}".encode()).hexdigest()[:32]
                findings.append(
                    FindingDraft(
                        plugin_id="jwt.expired",
                        severity="low",
                        title="Expired JWT exposed",
                        description=(
                            f"A JWT found via {source} is past its 'exp' expiration time."
                        ),
                        fingerprint=fp,
                        location=location,
                        evidence=evidence,
                    )
                )
        return findings
