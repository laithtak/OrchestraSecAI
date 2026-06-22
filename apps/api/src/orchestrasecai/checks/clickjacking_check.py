import hashlib

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck

VALID_XFO = ("deny", "sameorigin")


def _parse_csp_frame_ancestors(csp: str) -> list[str] | None:
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if parts and parts[0].lower() == "frame-ancestors":
            return [p.strip() for p in parts[1:]]
    return None


class ClickjackingCheck(SecurityCheck):
    plugin_id = "clickjacking"
    name = "Clickjacking Protection Check"
    phase = CheckPhase.PAGE
    aliases = ["clickjacking"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page:
            return []
        findings: list[FindingDraft] = []
        url = ctx.page.url
        headers_lower = {k.lower(): v for k, v in ctx.page.headers.items()}

        xfo = headers_lower.get("x-frame-options")
        csp = headers_lower.get("content-security-policy")
        frame_ancestors = _parse_csp_frame_ancestors(csp) if csp else None

        evidence = [
            {
                "evidence_type": "http_response",
                "payload": {
                    "x-frame-options": xfo,
                    "content-security-policy": csp,
                },
            }
        ]

        has_xfo = xfo is not None and xfo.strip() != ""
        has_frame_ancestors = frame_ancestors is not None

        if not has_xfo and not has_frame_ancestors:
            fp = hashlib.sha256(f"clickjacking.missing_protection:{url}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="clickjacking.missing_protection",
                    severity="medium",
                    title="Missing clickjacking protection",
                    description=(
                        f"Response from {url} has neither X-Frame-Options nor a CSP "
                        "frame-ancestors directive, leaving it vulnerable to clickjacking."
                    ),
                    fingerprint=fp,
                    location={"url": url, "header": "X-Frame-Options"},
                    evidence=evidence,
                )
            )
            return findings

        if has_frame_ancestors and any(v == "*" for v in (frame_ancestors or [])):
            fp = hashlib.sha256(f"clickjacking.permissive_frame_ancestors:{url}".encode()).hexdigest()[
                :32
            ]
            findings.append(
                FindingDraft(
                    plugin_id="clickjacking.permissive_frame_ancestors",
                    severity="medium",
                    title="Permissive CSP frame-ancestors",
                    description=(
                        f"CSP frame-ancestors on {url} allows any origin (*), which does not "
                        "protect against clickjacking."
                    ),
                    fingerprint=fp,
                    location={"url": url, "header": "Content-Security-Policy"},
                    evidence=evidence,
                )
            )

        if has_xfo and xfo.strip().lower() not in VALID_XFO and not has_frame_ancestors:
            fp = hashlib.sha256(f"clickjacking.weak_x_frame_options:{url}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="clickjacking.weak_x_frame_options",
                    severity="low",
                    title="Weak X-Frame-Options value",
                    description=(
                        f"X-Frame-Options on {url} has an unrecognized value '{xfo}'. "
                        "Use DENY or SAMEORIGIN."
                    ),
                    fingerprint=fp,
                    location={"url": url, "header": "X-Frame-Options"},
                    evidence=evidence,
                )
            )
        return findings
