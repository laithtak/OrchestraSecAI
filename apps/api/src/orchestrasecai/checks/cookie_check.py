import hashlib

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck


class CookieCheck(SecurityCheck):
    plugin_id = "cookie"
    name = "Cookie Security Check"
    phase = CheckPhase.PAGE
    aliases = ["cookie"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page or not ctx.page.cookies:
            return []
        findings: list[FindingDraft] = []
        for cookie in ctx.page.cookies:
            name = cookie.get("name", "unknown")
            flags = cookie.get("flags", {})
            issues = []
            if not flags.get("secure"):
                issues.append("Secure")
            if not flags.get("httponly"):
                issues.append("HttpOnly")
            if not flags.get("samesite"):
                issues.append("SameSite")
            for missing in issues:
                plugin_id = f"cookie.missing_{missing.lower()}"
                fp = hashlib.sha256(f"{plugin_id}:{ctx.page.url}:{name}".encode()).hexdigest()[:32]
                findings.append(
                    FindingDraft(
                        plugin_id=plugin_id,
                        severity="medium" if missing != "SameSite" else "low",
                        title=f"Cookie '{name}' missing {missing} attribute",
                        description=f"Set-Cookie for '{name}' on {ctx.page.url} is missing the {missing} flag.",
                        fingerprint=fp,
                        location={"url": ctx.page.url, "cookie_name": name},
                        evidence=[
                            {
                                "evidence_type": "http_response",
                                "payload": {"cookie": cookie},
                            }
                        ],
                    )
                )
        return findings
