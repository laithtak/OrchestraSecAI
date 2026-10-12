"""Destination-address safety checks shared by every scanner network path."""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

# Ranges that are never a legitimate public scan destination. Most are also covered by
# ``ipaddress`` properties; they are listed explicitly so the policy is auditable.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # "this" network
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, incl. cloud metadata 169.254.169.254
    ipaddress.ip_network("172.16.0.0/12"),  # RFC1918
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 relay anycast
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved + broadcast
    ipaddress.ip_network("::/128"),  # unspecified
    ipaddress.ip_network("::1/128"),  # loopback
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 (can embed private IPv4)
    ipaddress.ip_network("64:ff9b:1::/48"),  # local-use NAT64
    ipaddress.ip_network("100::/64"),  # discard-only
    ipaddress.ip_network("2001:db8::/32"),  # documentation
    ipaddress.ip_network("2002::/16"),  # 6to4 (can embed private IPv4)
    ipaddress.ip_network("fc00::/7"),  # unique local, incl. AWS IMDS fd00:ec2::254
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("ff00::/8"),  # multicast
]

DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0

Resolver = Callable[[str, int], Awaitable[list[str]]]


class SSRFError(ValueError):
    """Target URL failed SSRF safety checks."""


def _is_blocked_ip(ip_str: str) -> bool:
    """Return True when an address must never be contacted by the scanner (fails closed)."""
    try:
        addr = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        # IPv4-mapped / IPv4-compatible forms must be judged as the embedded IPv4 address.
        embedded = addr.ipv4_mapped or addr.sixtofour or (addr.teredo[1] if addr.teredo else None)
        if embedded is not None and _is_blocked_ip(str(embedded)):
            return True
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or not addr.is_global
    ):
        return True
    return any(addr in net for net in BLOCKED_NETWORKS)


def is_public_address(ip_str: str) -> bool:
    return not _is_blocked_ip(ip_str)


async def system_resolver(host: str, port: int) -> list[str]:
    """Resolve ``host`` without blocking the event loop."""
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
        timeout=DNS_RESOLUTION_TIMEOUT_SECONDS,
    )
    addresses: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in addresses:
            addresses.append(ip)
    return addresses


async def resolve_public_addresses(
    host: str, port: int, resolver: Resolver | None = None
) -> list[str]:
    """Resolve ``host`` and require every returned address to be public.

    A hostname with any non-public answer is rejected outright: accepting it would let
    an attacker-controlled DNS zone mix public and internal answers.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if _is_blocked_ip(host):
            raise SSRFError("Target resolves to a blocked private or reserved IP range")
        return [host]

    try:
        addresses = await (resolver or system_resolver)(host, port)
    except (OSError, TimeoutError) as exc:
        raise SSRFError("Cannot resolve hostname") from exc
    if not addresses:
        raise SSRFError("Cannot resolve hostname")
    for ip in addresses:
        if _is_blocked_ip(ip):
            raise SSRFError("Target resolves to a blocked private or reserved IP range")
    return addresses


def validate_target_url(url: str) -> None:
    """Synchronous URL check kept for callers outside the async scanner path."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError("Only http/https URLs allowed")
    if not parsed.hostname:
        raise SSRFError("Invalid URL hostname")
    if parsed.username or parsed.password:
        raise SSRFError("Credentials in URLs are not allowed")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise SSRFError("Invalid URL port") from exc
    try:
        infos = socket.getaddrinfo(parsed.hostname, port)
    except socket.gaierror as exc:
        raise SSRFError("Cannot resolve hostname") from exc
    if not infos:
        raise SSRFError("Cannot resolve hostname")
    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            raise SSRFError("Target resolves to a blocked private or reserved IP range")
