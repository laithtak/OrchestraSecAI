import hashlib

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("header.missing_strict_transport_security", "medium"),
    "Content-Security-Policy": ("header.missing_content_security_policy", "medium"),
    "X-Content-Type-Options": ("header.missing_x_content_type_options", "low"),
    "Referrer-Policy": ("header.missing_referrer_policy", "info"),
}


class HeaderCheck(SecurityCheck):
    plugin_id = "header"
    name = "Security Headers Check"
    phase = CheckPhase.PAGE
    aliases = ["header"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page:
            return []
        findings: list[FindingDraft] = []
        headers_lower = {k.lower(): v for k, v in ctx.page.headers.items()}
        for header, (plugin_suffix, severity) in SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                fp = hashlib.sha256(
                    f"{plugin_suffix}:{ctx.page.url}:{header}".encode()
                ).hexdigest()[:32]
                findings.append(
                    FindingDraft(
                        plugin_id=plugin_suffix,
                        severity=severity,
                        title=f"Missing {header} header",
                        description=f"Response from {ctx.page.url} does not include the {header} security header.",
                        fingerprint=fp,
                        location={"url": ctx.page.url, "header": header},
                        evidence=[
                            {
                                "evidence_type": "http_response",
                                "payload": {"headers": dict(ctx.page.headers)},
                            }
                        ],
                    )
                )
        return findings
