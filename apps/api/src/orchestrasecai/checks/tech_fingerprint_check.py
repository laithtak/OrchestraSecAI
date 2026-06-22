import hashlib
import re

from orchestrasecai.checks.base import CheckContext, CheckPhase, FindingDraft, SecurityCheck

META_GENERATOR_PATTERN = re.compile(
    r"<meta[^>]+name=['\"]generator['\"][^>]*content=['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

# Body signals: (technology name, compiled regex over body_snippet)
BODY_SIGNALS: list[tuple[str, re.Pattern[str]]] = [
    ("jQuery", re.compile(r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)?", re.IGNORECASE)),
    ("React", re.compile(r"\breact(?:-dom)?[.-]", re.IGNORECASE)),
    ("Next.js", re.compile(r"__NEXT_DATA__", re.IGNORECASE)),
    ("Vue.js", re.compile(r"\bvue(?:\.runtime)?[.-]", re.IGNORECASE)),
    ("Angular", re.compile(r"ng-version=|angular[.-]", re.IGNORECASE)),
    ("WordPress", re.compile(r"/wp-(?:content|includes|json)/", re.IGNORECASE)),
    ("Bootstrap", re.compile(r"bootstrap[.-]", re.IGNORECASE)),
]

# Cookie name -> technology
COOKIE_SIGNALS: dict[str, str] = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "laravel_session": "Laravel",
    "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "ASP",
    "ci_session": "CodeIgniter",
    "_rails_session": "Ruby on Rails",
    "wordpress_logged_in": "WordPress",
}

# Header name (lower) -> technology label prefix
HEADER_SIGNALS = ("server", "x-powered-by", "x-generator", "x-aspnet-version")


def _fingerprint(plugin_id: str, url: str, discriminator: str) -> str:
    return hashlib.sha256(f"{plugin_id}:{url}:{discriminator}".encode()).hexdigest()[:32]


def _split_version(value: str) -> tuple[str, str | None]:
    match = re.search(r"([0-9]+(?:\.[0-9]+)+)", value)
    version = match.group(1) if match else None
    name = value.split("/")[0].strip() if "/" in value else value.strip()
    return name[:80], version


class TechFingerprintCheck(SecurityCheck):
    plugin_id = "tech_fingerprint"
    name = "Technology Fingerprint Check"
    phase = CheckPhase.PAGE
    aliases = ["tech_fingerprint"]

    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        if not ctx.page:
            return []
        url = ctx.page.url
        headers_lower = {k.lower(): v for k, v in ctx.page.headers.items()}
        body = ctx.page.body_snippet or ""
        technologies: list[dict[str, str | None]] = []
        seen: set[str] = set()

        def add(name: str, version: str | None, source: str) -> None:
            key = name.lower()
            if not name or key in seen:
                return
            seen.add(key)
            technologies.append({"name": name, "version": version, "source": source})

        for header in HEADER_SIGNALS:
            raw = headers_lower.get(header)
            if raw:
                name, version = _split_version(raw)
                add(name, version, f"header:{header}")

        meta_match = META_GENERATOR_PATTERN.search(body)
        if meta_match:
            name, version = _split_version(meta_match.group(1))
            add(name, version, "meta:generator")

        for name, pattern in BODY_SIGNALS:
            match = pattern.search(body)
            if match:
                version = None
                if match.groups():
                    version = match.group(1)
                add(name, version, "body")

        for cookie in ctx.page.cookies or []:
            cookie_name = (cookie.get("name") or "").lower()
            tech = COOKIE_SIGNALS.get(cookie_name)
            if tech:
                add(tech, None, f"cookie:{cookie_name}")

        if not technologies:
            return []

        return [
            FindingDraft(
                plugin_id="tech_fingerprint.detected",
                severity="info",
                title="Technology stack fingerprinted",
                description=(
                    f"Detected {len(technologies)} technology signal(s) on {url}: "
                    + ", ".join(t["name"] for t in technologies)[:200]
                ),
                fingerprint=_fingerprint(
                    "tech_fingerprint.detected",
                    url,
                    ",".join(sorted(seen)),
                ),
                location={"url": url, "technologies": technologies},
                evidence=[
                    {
                        "evidence_type": "fingerprint",
                        "payload": {"technologies": technologies},
                    }
                ],
            )
        ]
