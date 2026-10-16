import socket

import pytest

from orchestrasecai.security.ssrf import (
    SSRFError,
    _is_blocked_ip,
    resolve_public_addresses,
    validate_target_url,
)


def test_blocks_localhost():
    with pytest.raises(SSRFError):
        validate_target_url("http://localhost/")


def test_allows_public_https(monkeypatch):
    def fake_getaddrinfo(host, port):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    validate_target_url("https://example.com/")


def test_rejects_credentials_in_url():
    with pytest.raises(SSRFError):
        validate_target_url("https://user:pass@example.com/")


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
        "224.0.0.1",  # multicast
        "255.255.255.255",
        "198.18.0.1",
        "::1",
        "::",
        "fe80::1",
        "fd00:ec2::254",  # AWS IMDS IPv6
        "ff02::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:169.254.169.254",
        "64:ff9b::a00:1",  # NAT64-embedded 10.0.0.1
        "2002:0a00:0001::1",  # 6to4-embedded 10.0.0.1
        "not-an-ip",
    ],
)
def test_blocked_addresses(ip):
    assert _is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_allowed(ip):
    assert _is_blocked_ip(ip) is False


@pytest.mark.asyncio
async def test_resolve_public_addresses_rejects_any_private_answer():
    async def resolver(host, port):
        return ["93.184.216.34", "127.0.0.1"]

    with pytest.raises(SSRFError):
        await resolve_public_addresses("example.com", 443, resolver)


@pytest.mark.asyncio
async def test_resolve_public_addresses_maps_resolver_timeout():
    async def resolver(host, port):
        raise TimeoutError

    with pytest.raises(SSRFError):
        await resolve_public_addresses("example.com", 443, resolver)
