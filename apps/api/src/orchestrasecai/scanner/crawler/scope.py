import re
from urllib.parse import urljoin, urlparse, urlunparse

from orchestrasecai.security.scope import ScopeError, target_scope

_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
MAX_LINKS_PER_PAGE = 500


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", parsed.query, ""))


def is_in_scope(url: str, base_url: str, allowed_hosts: list[str]) -> bool:
    """Exact-host scope check: the target host plus explicitly allowed subdomains."""
    try:
        scope = target_scope(base_url, allowed_hosts)
    except ScopeError:
        return False
    return scope.contains(url)


def is_blocked_path(url: str, patterns: list[str]) -> bool:
    path = urlparse(url).path.lower()
    return any(pattern and pattern.lower() in path for pattern in patterns)


def extract_links(base_url: str, html: str) -> list[str]:
    links = []
    for match in _HREF_RE.finditer(html):
        href = match.group(1)
        if href.startswith(("mailto:", "javascript:", "#", "tel:", "data:")):
            continue
        links.append(normalize_url(urljoin(base_url, href)))
        if len(links) >= MAX_LINKS_PER_PAGE:
            break
    return links
