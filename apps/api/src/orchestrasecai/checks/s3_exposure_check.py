import hashlib
import re

import httpx

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck
from orchestrasecai.security.passive_http import assert_passive_method
from orchestrasecai.security.ssrf import validate_target_url

BUCKET_PATTERN = re.compile(
    r"https?://[A-Za-z0-9._-]+\.s3[A-Za-z0-9.-]*\.amazonaws\.com[^\s\"'<>)]*"
    r"|https?://s3[A-Za-z0-9.-]*\.amazonaws\.com/[A-Za-z0-9._-]+[^\s\"'<>)]*"
    r"|https?://storage\.googleapis\.com/[A-Za-z0-9._-]+[^\s\"'<>)]*"
    r"|https?://[A-Za-z0-9._-]+\.blob\.core\.windows\.net[^\s\"'<>)]*"
)


class S3ExposureCheck(SecurityCheck):
    plugin_id = "s3_exposure"
    name = "Cloud Storage Exposure Check"
    phase = CheckPhase.PAGE
    aliases = ["s3_exposure"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.scan_config.get("enable_active_network_checks"):
            return []
        if not ctx.page:
            return []
        url = ctx.page.url
        findings: list[FindingDraft] = []

        haystack = ctx.page.body_snippet or ""
        haystack += "\n" + "\n".join(f"{k}: {v}" for k, v in ctx.page.headers.items())
        bucket_urls = sorted(set(BUCKET_PATTERN.findall(haystack)))

        for bucket_url in bucket_urls:
            status: int | None = None
            try:
                assert_passive_method("HEAD")
                validate_target_url(bucket_url)
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    resp = await client.head(bucket_url)
                status = resp.status_code
            except Exception:
                status = None

            if status == 200:
                fp = hashlib.sha256(
                    f"s3_exposure.public_bucket:{url}:{bucket_url}".encode()
                ).hexdigest()[:32]
                findings.append(
                    FindingDraft(
                        plugin_id="s3_exposure.public_bucket",
                        severity="high",
                        title="Publicly accessible cloud storage bucket",
                        description=(
                            f"Cloud storage URL {bucket_url} referenced by {url} returned HTTP "
                            "200 to an unauthenticated request."
                        ),
                        fingerprint=fp,
                        location={"url": url, "bucket_url": bucket_url, "status": status},
                        evidence=[
                            {
                                "evidence_type": "http_response",
                                "payload": {"bucket_url": bucket_url, "status": status},
                            }
                        ],
                    )
                )
            else:
                fp = hashlib.sha256(
                    f"s3_exposure.bucket_reference:{url}:{bucket_url}".encode()
                ).hexdigest()[:32]
                findings.append(
                    FindingDraft(
                        plugin_id="s3_exposure.bucket_reference",
                        severity="info",
                        title="Cloud storage bucket reference",
                        description=(
                            f"Cloud storage URL {bucket_url} is referenced by {url}."
                        ),
                        fingerprint=fp,
                        location={"url": url, "bucket_url": bucket_url, "status": status},
                        evidence=[
                            {
                                "evidence_type": "http_response",
                                "payload": {"bucket_url": bucket_url, "status": status},
                            }
                        ],
                    )
                )
        return findings
