import hashlib
import re

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
API_KEY_PATTERN = re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}")
DEBUG_HEADERS = ("X-Debug", "X-Debug-Token", "X-Powered-By", "Server")


class DisclosureCheck(SecurityCheck):
    plugin_id = "disclosure"
    name = "Information Disclosure Check"
    phase = CheckPhase.PAGE
    aliases = ["disclosure"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page:
            return []
        findings: list[FindingDraft] = []
        body = ctx.page.body_snippet or ""

        for header in DEBUG_HEADERS:
            val = next(
                (v for k, v in ctx.page.headers.items() if k.lower() == header.lower()),
                None,
            )
            if val and header.lower() in ("x-debug", "x-debug-token", "server"):
                fp = hashlib.sha256(f"disclosure.debug_header:{ctx.page.url}:{header}".encode()).hexdigest()[
                    :32
                ]
                findings.append(
                    FindingDraft(
                        plugin_id="disclosure.debug_header",
                        severity="low",
                        title=f"Debug/banner header exposed: {header}",
                        description=f"Response includes {header}: {val[:100]}",
                        fingerprint=fp,
                        location={"url": ctx.page.url, "header": header},
                        evidence=[{"evidence_type": "http_response", "payload": {header: val}}],
                    )
                )

        emails = EMAIL_PATTERN.findall(body)[:3]
        for email in emails:
            fp = hashlib.sha256(f"disclosure.email:{ctx.page.url}:{email}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="disclosure.email_in_body",
                    severity="info",
                    title="Email address found in page content",
                    description=f"Possible email disclosure: {email}",
                    fingerprint=fp,
                    location={"url": ctx.page.url},
                    evidence=[{"evidence_type": "http_response", "payload": {"snippet": body[:200]}}],
                )
            )

        if API_KEY_PATTERN.search(body):
            fp = hashlib.sha256(f"disclosure.api_key_pattern:{ctx.page.url}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="disclosure.possible_api_key",
                    severity="high",
                    title="Possible API key or secret in page content",
                    description="Response body matches common API key/secret patterns.",
                    fingerprint=fp,
                    location={"url": ctx.page.url},
                    evidence=[{"evidence_type": "http_response", "payload": {"snippet": body[:200]}}],
                )
            )
        return findings
