from urllib.parse import urljoin, urlparse, urlunparse


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", parsed.query, ""))


def registrable_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return host.lower()
    return ".".join(parts[-2:])


def is_in_scope(url: str, base_url: str, allowed_hosts: list[str]) -> bool:
    parsed = urlparse(url)
    base_parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname or ""
    if allowed_hosts:
        return host in allowed_hosts or host.endswith(tuple(f".{h}" for h in allowed_hosts))
    base_host = base_parsed.hostname or ""
    return registrable_domain(host) == registrable_domain(base_host)


def is_blocked_path(url: str, patterns: list[str]) -> bool:
    path = urlparse(url).path.lower()
    for pattern in patterns:
        if pattern.lower() in path:
            return True
    return False


def extract_links(base_url: str, html: str) -> list[str]:
    import re

    links = []
    for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
        href = match.group(1)
        if href.startswith(("mailto:", "javascript:", "#", "tel:")):
            continue
        links.append(normalize_url(urljoin(base_url, href)))
    return links
