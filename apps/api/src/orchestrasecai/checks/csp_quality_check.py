import hashlib

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck

KEY_DIRECTIVES = {
    "default-src": "medium",
    "object-src": "medium",
    "base-uri": "low",
}


def _fingerprint(plugin_id: str, url: str, discriminator: str) -> str:
    return hashlib.sha256(f"{plugin_id}:{url}:{discriminator}".encode()).hexdigest()[:32]


def _parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives[name] = [t.strip() for t in tokens[1:]]
    return directives


class CspQualityCheck(SecurityCheck):
    plugin_id = "csp_quality"
    name = "CSP Quality Check"
    phase = CheckPhase.PAGE
    aliases = ["csp_quality"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page:
            return []
        headers_lower = {k.lower(): v for k, v in ctx.page.headers.items()}
        csp = headers_lower.get("content-security-policy")
        if not csp:
            return []

        url = ctx.page.url
        directives = _parse_csp(csp)
        findings: list[FindingDraft] = []

        def add(plugin_id: str, severity: str, title: str, description: str, directive: str) -> None:
            findings.append(
                FindingDraft(
                    plugin_id=plugin_id,
                    severity=severity,
                    title=title,
                    description=description,
                    fingerprint=_fingerprint(plugin_id, url, directive),
                    location={"url": url, "directive": directive},
                    evidence=[
                        {
                            "evidence_type": "http_response",
                            "payload": {"directive": directive, "sources": directives.get(directive, [])},
                        }
                    ],
                )
            )

        for directive, sources in directives.items():
            lowered = [s.lower() for s in sources]
            if "'unsafe-inline'" in lowered or "'unsafe-eval'" in lowered:
                unsafe = "'unsafe-inline'" if "'unsafe-inline'" in lowered else "'unsafe-eval'"
                is_script = directive in ("script-src", "default-src")
                add(
                    "csp_quality.unsafe_directive",
                    "high" if is_script else "medium",
                    f"CSP {directive} allows {unsafe}",
                    f"The CSP {directive} directive on {url} includes {unsafe}, weakening XSS protection.",
                    directive,
                )
            if "*" in sources:
                add(
                    "csp_quality.wildcard_source",
                    "medium",
                    f"CSP {directive} allows wildcard source",
                    f"The CSP {directive} directive on {url} uses a wildcard (*) source, permitting any host.",
                    directive,
                )

        for directive, severity in KEY_DIRECTIVES.items():
            if directive not in directives:
                add(
                    "csp_quality.missing_directive",
                    severity,
                    f"CSP missing {directive} directive",
                    f"The CSP on {url} does not define {directive}, reducing its effectiveness.",
                    directive,
                )

        return findings
