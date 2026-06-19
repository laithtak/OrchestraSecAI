from unittest.mock import MagicMock

from orchestrasecai.domain.verification import (
    can_scan_unverified_target,
    check_dns_txt_verification,
    expected_txt_value,
    target_hostname,
    verification_instructions,
)


def test_target_hostname():
    assert target_hostname("https://example.com/path") == "example.com"


def test_verification_instructions():
    info = verification_instructions("abc-123", "example.com")
    assert info["record_name"] == "_orchestrasec.example.com"
    assert info["record_value"] == "verify-abc-123"


def test_can_scan_unverified_target_is_false():
    assert can_scan_unverified_target() is False


def test_check_dns_txt_verification_match(monkeypatch):
    target_id = "abc-123"
    expected = expected_txt_value(target_id)

    answer = MagicMock()
    answer.strings = [expected.encode("utf-8")]

    def fake_resolve(name, rtype):
        assert name == "_orchestrasec.example.com"
        assert rtype == "TXT"
        return [answer]

    monkeypatch.setattr("orchestrasecai.domain.verification.dns.resolver.resolve", fake_resolve)
    assert check_dns_txt_verification("example.com", target_id) is True


def test_check_dns_txt_verification_no_match(monkeypatch):
    import dns.resolver

    def fake_resolve(_name, _rtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr("orchestrasecai.domain.verification.dns.resolver.resolve", fake_resolve)
    assert check_dns_txt_verification("example.com", "abc-123") is False
