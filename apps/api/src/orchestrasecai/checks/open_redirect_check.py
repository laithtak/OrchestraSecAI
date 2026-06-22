import hashlib
from urllib.parse import parse_qsl, urlsplit

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck

REDIRECT_PARAMS = {
    "next",
    "url",
    "redirect",
    "return",
    "returnurl",
    "dest",
    "destination",
    "continue",
    "r",
    "u",
}


def _fingerprint(plugin_id: str, url: str, discriminator: str) -> str:
    return hashlib.sha256(f"{plugin_id}:{url}:{discriminator}".encode()).hexdigest()[:32]


def _looks_like_target(value: str) -> bool:
    if not value:
        return False
    candidate = value.strip()
    if candidate.startswith(("http://", "https://", "//")):
        return True
    if candidate.startswith("/"):
        return True
    return False


class OpenRedirectCheck(SecurityCheck):
    plugin_id = "open_redirect"
    name = "Open Redirect Candidate Check"
    phase = CheckPhase.PAGE
    aliases = ["open_redirect"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page:
            return []
        url = ctx.page.url
        query = urlsplit(url).query
        if not query:
            return []

        findings: list[FindingDraft] = []
        seen: set[str] = set()
        for name, value in parse_qsl(query, keep_blank_values=True):
            if name.lower() not in REDIRECT_PARAMS:
                continue
            if not _looks_like_target(value):
                continue
            if name in seen:
                continue
            seen.add(name)
            findings.append(
                FindingDraft(
                    plugin_id="open_redirect.candidate_param",
                    severity="low",
                    title=f"Possible open redirect parameter '{name}'",
                    description=(
                        f"Query parameter '{name}' on {url} carries a URL/path-like value, "
                        "which may be vulnerable to open redirection and warrants active testing."
                    ),
                    fingerprint=_fingerprint("open_redirect.candidate_param", url, name),
                    location={"url": url, "param": name, "value": value[:200]},
                    evidence=[
                        {
                            "evidence_type": "url",
                            "payload": {"param": name, "value": value[:200]},
                        }
                    ],
                )
            )
        return findings
