import hashlib

import httpx

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck
from orchestrasecai.security.passive_http import assert_passive_method
from orchestrasecai.security.ssrf import validate_target_url


class SubdomainEnumCheck(SecurityCheck):
    plugin_id = "subdomain_enum"
    name = "Subdomain Enumeration Check"
    phase = CheckPhase.HOST
    aliases = ["subdomain_enum"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.scan_config.get("enable_active_network_checks"):
            return []
        if not ctx.host:
            return []
        hostname = ctx.host.hostname
        findings: list[FindingDraft] = []
        subdomains: set[str] = set()

        url = f"https://crt.sh/?q=%25.{hostname}&output=json"
        try:
            assert_passive_method("GET")
            validate_target_url(url)
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(url)
            if resp.status_code == 200:
                for entry in resp.json():
                    name_value = entry.get("name_value", "") if isinstance(entry, dict) else ""
                    for line in str(name_value).splitlines():
                        candidate = line.strip().lower().lstrip("*.")
                        if candidate and candidate.endswith(hostname.lower()):
                            subdomains.add(candidate)
        except Exception:
            return findings

        if subdomains:
            ordered = sorted(subdomains)
            fp = hashlib.sha256(f"subdomain_enum.discovered:{hostname}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="subdomain_enum.discovered",
                    severity="info",
                    title=f"Discovered {len(ordered)} subdomains for {hostname}",
                    description=(
                        f"Certificate transparency logs (crt.sh) revealed {len(ordered)} "
                        f"subdomains for {hostname}."
                    ),
                    fingerprint=fp,
                    location={"host": hostname, "subdomains": ordered},
                    evidence=[
                        {
                            "evidence_type": "subdomain_enumeration",
                            "payload": {"source": "crt.sh", "subdomains": ordered[:50]},
                        }
                    ],
                )
            )
        return findings
