import pytest

from orchestrasecai.security.ssrf import SSRFError, validate_target_url


def test_blocks_localhost():
    with pytest.raises(SSRFError):
        validate_target_url("http://localhost/")


def test_allows_public_https(monkeypatch):
    def fake_getaddrinfo(host, port):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    import socket

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    validate_target_url("https://example.com/")
