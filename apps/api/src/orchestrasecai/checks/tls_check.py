import hashlib
import ssl
import socket
from datetime import UTC, datetime

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck


class TLSCheck(SecurityCheck):
    plugin_id = "tls"
    name = "TLS Configuration Check"
    phase = CheckPhase.HOST
    aliases = ["tls"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.host:
            return []
        hostname = ctx.host.hostname
        if ctx.host.tls_info:
            return self._analyze_tls(hostname, ctx.host.tls_info)

        tls_info = await self._probe_tls(hostname)
        ctx.host.tls_info = tls_info
        return self._analyze_tls(hostname, tls_info)

    async def _probe_tls(self, hostname: str) -> dict:
        loop = __import__("asyncio").get_event_loop()
        return await loop.run_in_executor(None, self._sync_probe, hostname)

    def _sync_probe(self, hostname: str) -> dict:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
        not_after = cert.get("notAfter")
        expiry = None
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        return {
            "version": version,
            "cipher": cipher,
            "cert_expiry": expiry.isoformat() if expiry else None,
            "subject": dict(x[0] for x in cert.get("subject", ())),
        }

    def _analyze_tls(self, hostname: str, tls_info: dict) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        version = tls_info.get("version", "")
        if version and version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            fp = hashlib.sha256(f"tls.weak_protocol:{hostname}:{version}".encode()).hexdigest()[:32]
            findings.append(
                FindingDraft(
                    plugin_id="tls.weak_protocol",
                    severity="high",
                    title=f"Weak TLS protocol: {version}",
                    description=f"Host {hostname} negotiates deprecated protocol {version}.",
                    fingerprint=fp,
                    location={"host": hostname},
                    evidence=[{"evidence_type": "tls_inspection", "payload": tls_info}],
                )
            )
        expiry_str = tls_info.get("cert_expiry")
        if expiry_str:
            expiry = datetime.fromisoformat(expiry_str)
            days_left = (expiry - datetime.now(UTC)).days
            if days_left < 30:
                fp = hashlib.sha256(f"tls.cert_expiring:{hostname}".encode()).hexdigest()[:32]
                findings.append(
                    FindingDraft(
                        plugin_id="tls.cert_expiring",
                        severity="medium" if days_left > 7 else "high",
                        title="TLS certificate expiring soon",
                        description=f"Certificate for {hostname} expires in {days_left} days.",
                        fingerprint=fp,
                        location={"host": hostname},
                        evidence=[{"evidence_type": "tls_inspection", "payload": tls_info}],
                    )
                )
        return findings
