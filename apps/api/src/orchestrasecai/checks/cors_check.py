import hashlib

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck


def _fingerprint(plugin_id: str, url: str, discriminator: str) -> str:
    return hashlib.sha256(f"{plugin_id}:{url}:{discriminator}".encode()).hexdigest()[:32]


class CorsCheck(SecurityCheck):
    plugin_id = "cors"
    name = "CORS Misconfiguration Check"
    phase = CheckPhase.PAGE
    aliases = ["cors"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page:
            return []
        headers_lower = {k.lower(): v for k, v in ctx.page.headers.items()}
        acao = headers_lower.get("access-control-allow-origin")
        if acao is None:
            return []
        acac = (headers_lower.get("access-control-allow-credentials") or "").strip().lower()
        credentials = acac == "true"
        acao_value = acao.strip()
        url = ctx.page.url
        findings: list[FindingDraft] = []

        evidence = [
            {
                "evidence_type": "http_response",
                "payload": {
                    "Access-Control-Allow-Origin": acao_value[:200],
                    "Access-Control-Allow-Credentials": acac,
                },
            }
        ]

        if acao_value == "*" and credentials:
            findings.append(
                FindingDraft(
                    plugin_id="cors.wildcard_with_credentials",
                    severity="high",
                    title="CORS wildcard origin with credentials",
                    description=(
                        f"{url} returns Access-Control-Allow-Origin: * together with "
                        "Access-Control-Allow-Credentials: true, exposing authenticated "
                        "responses to any origin."
                    ),
                    fingerprint=_fingerprint("cors.wildcard_with_credentials", url, "acao"),
                    location={"url": url, "header": "Access-Control-Allow-Origin"},
                    evidence=evidence,
                )
            )
        elif acao_value.lower() == "null":
            findings.append(
                FindingDraft(
                    plugin_id="cors.reflected_origin",
                    severity="medium",
                    title="CORS allows null origin",
                    description=(
                        f"{url} returns Access-Control-Allow-Origin: null, which can be "
                        "abused by sandboxed iframes and other privileged contexts."
                    ),
                    fingerprint=_fingerprint("cors.reflected_origin", url, "null"),
                    location={"url": url, "header": "Access-Control-Allow-Origin"},
                    evidence=evidence,
                )
            )
        elif credentials and acao_value not in ("", "*"):
            findings.append(
                FindingDraft(
                    plugin_id="cors.reflected_origin",
                    severity="medium",
                    title="CORS reflects a specific origin with credentials",
                    description=(
                        f"{url} returns a specific Access-Control-Allow-Origin "
                        f"({acao_value[:100]}) with credentials enabled, which may reflect "
                        "an attacker-controlled origin."
                    ),
                    fingerprint=_fingerprint("cors.reflected_origin", url, acao_value),
                    location={"url": url, "header": "Access-Control-Allow-Origin"},
                    evidence=evidence,
                )
            )
        elif acao_value == "*":
            findings.append(
                FindingDraft(
                    plugin_id="cors.wildcard_origin",
                    severity="low",
                    title="CORS wildcard origin",
                    description=(
                        f"{url} returns Access-Control-Allow-Origin: *, allowing any origin "
                        "to read non-credentialed responses."
                    ),
                    fingerprint=_fingerprint("cors.wildcard_origin", url, "acao"),
                    location={"url": url, "header": "Access-Control-Allow-Origin"},
                    evidence=evidence,
                )
            )
        return findings
