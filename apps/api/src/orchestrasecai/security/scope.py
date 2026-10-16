"""Canonical scan scope derived from a verified target.

Scope is exact-host: a target authorises its own hostname plus explicitly listed
``allowed_hosts`` that are the same host or subdomains of it. There is no implicit
"same registrable domain" expansion, so sibling hosts, redirects to other hosts and
LLM-proposed URLs on other hosts are always out of scope.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_ALLOWED_HOSTS = 20
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ScopeError(ValueError):
    """A URL or target definition violates scope rules."""


def normalize_hostname(host: str) -> str:
    """Lower-case, strip a trailing dot and IDNA-encode a DNS hostname."""
    candidate = (host or "").strip().rstrip(".").lower()
    if not candidate:
        raise ScopeError("Hostname is required")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError("Hostname is not a valid internationalized domain name") from exc
    if len(candidate) > 253:
        raise ScopeError("Hostname is too long")
    labels = candidate.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise ScopeError("Hostname contains invalid characters")
    return candidate


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def effective_port(scheme: str, port: int | None) -> int:
    return port if port is not None else DEFAULT_PORTS[scheme]


def _split(url: str):
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ScopeError("Invalid URL") from exc
    return parts, port


def _validate_domain_host(host: str) -> str:
    if is_ip_literal(host):
        raise ScopeError("Targets must use a DNS hostname, not an IP address")
    normalized = normalize_hostname(host)
    if "." not in normalized:
        raise ScopeError("Targets must use a fully qualified domain name")
    return normalized


@dataclass(frozen=True)
class TargetScope:
    base_url: str
    hostname: str
    hosts: frozenset[str]
    ports: frozenset[int]
    schemes: frozenset[str] = ALLOWED_SCHEMES

    def check(self, url: str) -> str:
        """Return the normalized hostname of ``url`` or raise ``ScopeError``."""
        parts, port = _split(url)
        scheme = (parts.scheme or "").lower()
        if scheme not in self.schemes:
            raise ScopeError(f"Scheme not allowed: {scheme or 'none'}")
        if parts.username or parts.password:
            raise ScopeError("Credentials in URLs are not allowed")
        if not parts.hostname:
            raise ScopeError("URL has no hostname")
        try:
            host = normalize_hostname(parts.hostname)
        except ScopeError as exc:
            raise ScopeError("URL hostname is invalid") from exc
        if host not in self.hosts:
            raise ScopeError(f"Host out of scope: {host}")
        if effective_port(scheme, port) not in self.ports:
            raise ScopeError(f"Port out of scope: {effective_port(scheme, port)}")
        return host

    def contains(self, url: str) -> bool:
        try:
            self.check(url)
        except ScopeError:
            return False
        return True


def validate_target_definition(base_url: str, allowed_hosts: list[str] | None) -> TargetScope:
    """Validate an operator-supplied target and return its canonical scope."""
    parts, port = _split((base_url or "").strip())
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ScopeError("Only http/https targets are allowed")
    if parts.username or parts.password:
        raise ScopeError("Credentials in URLs are not allowed")
    if not parts.hostname:
        raise ScopeError("Target URL has no hostname")
    hostname = _validate_domain_host(parts.hostname)

    hosts = {hostname}
    for raw in allowed_hosts or []:
        if "*" in raw or "/" in raw or ":" in raw:
            raise ScopeError("allowed_hosts entries must be plain hostnames (no wildcards/ports)")
        host = _validate_domain_host(raw)
        if host != hostname and not host.endswith(f".{hostname}"):
            raise ScopeError(
                f"allowed_hosts entry {host} is not {hostname} or one of its subdomains"
            )
        hosts.add(host)
    if len(hosts) > MAX_ALLOWED_HOSTS:
        raise ScopeError(f"At most {MAX_ALLOWED_HOSTS} hosts may be in scope")

    netloc = hostname if port is None else f"{hostname}:{port}"
    canonical = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    ports = {80, 443, effective_port(scheme, port)}
    return TargetScope(
        base_url=canonical,
        hostname=hostname,
        hosts=frozenset(hosts),
        ports=frozenset(ports),
    )


def target_scope(base_url: str, allowed_hosts: list[str] | None) -> TargetScope:
    return validate_target_definition(base_url, allowed_hosts)
