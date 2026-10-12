"""DNS TXT ownership verification (challenge issuing, checking, authorization gate).

Replaces tests for the removed deterministic ``verify-<target_id>`` scheme, which used a
guessable, non-expiring value with no binding to a verified domain.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import dns.exception
import dns.resolver
import pytest

from orchestrasecai.domain import verification as v
from orchestrasecai.persistence.tables.core import (
    ChallengeStatus,
    DomainVerificationChallenge,
    ScanTarget,
    VerificationStatus,
)

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


def make_target(**kw) -> ScanTarget:
    params = {
        "id": uuid4(),
        "org_id": uuid4(),
        "project_id": uuid4(),
        "base_url": "https://app.example.com/",
        "allowed_hosts": [],
        "verification_status": VerificationStatus.unverified,
    }
    params.update(kw)
    return ScanTarget(**params)


def fake_db() -> MagicMock:
    db = MagicMock()
    db.flush = AsyncMock()
    db.add = MagicMock()
    return db


@pytest.fixture
def no_live_challenge(monkeypatch):
    monkeypatch.setattr(v, "current_challenge", AsyncMock(return_value=None))


async def issue(target, monkeypatch) -> v.IssuedChallenge:
    monkeypatch.setattr(v, "current_challenge", AsyncMock(return_value=None))
    issued = await v.issue_challenge(fake_db(), target, user_id=None, now=NOW)
    monkeypatch.setattr(v, "current_challenge", AsyncMock(return_value=issued.challenge))
    return issued


def test_instructions_use_dedicated_record_name():
    info = v.verification_instructions("app.example.com", "tok")
    assert info["record_name"] == "_orchestrasec.app.example.com"
    assert info["record_value"] == "orchestrasec-verify=tok"
    assert v.verification_instructions("app.example.com")["record_value"] is None


def test_target_hostname_is_canonical():
    assert v.target_hostname("https://App.Example.COM./x") == "app.example.com"
    assert v.target_hostname("https://10.0.0.1/") is None


@pytest.mark.asyncio
async def test_issue_challenge_creates_random_hashed_expiring_token(monkeypatch):
    target = make_target()
    first = await issue(target, monkeypatch)
    second = await issue(make_target(), monkeypatch)

    assert first.token != second.token
    assert len(first.token) >= 43  # 32 random bytes, urlsafe base64
    ch = first.challenge
    assert ch.token_hash == v.hash_token(first.token)
    assert first.token not in (ch.token_hash, ch.token_hint * 10)
    assert ch.token_hint == first.token[:6]
    assert ch.domain == "app.example.com"
    assert ch.org_id == target.org_id and ch.target_id == target.id
    assert ch.expires_at == NOW + timedelta(hours=72)
    assert target.verification_status == VerificationStatus.pending


@pytest.mark.asyncio
async def test_rotation_supersedes_live_challenge_and_revokes_verification(monkeypatch):
    target = make_target(
        verification_status=VerificationStatus.verified,
        verified_domain="app.example.com",
        verified_at=NOW,
        verification_expires_at=NOW + timedelta(days=30),
    )
    old = DomainVerificationChallenge(status=ChallengeStatus.verified)
    monkeypatch.setattr(v, "current_challenge", AsyncMock(return_value=old))
    issued = await v.issue_challenge(fake_db(), target, user_id=None, now=NOW)
    assert old.status == ChallengeStatus.superseded
    assert issued.challenge.status == ChallengeStatus.pending
    assert target.verification_status == VerificationStatus.pending
    assert target.verified_domain is None


@pytest.mark.asyncio
async def test_successful_check_binds_domain_and_expiry(monkeypatch):
    target = make_target()
    issued = await issue(target, monkeypatch)

    async def fetcher(name):
        assert name == "_orchestrasec.app.example.com"
        return ["unrelated=1", f'"orchestrasec-verify={issued.token}"']

    result = await v.check_challenge(fake_db(), target, now=NOW, fetcher=fetcher)
    assert result == v.CheckResult.verified
    assert target.verification_status == VerificationStatus.verified
    assert target.verified_domain == "app.example.com"
    assert target.verification_expires_at == NOW + timedelta(days=30)
    assert issued.challenge.status == ChallengeStatus.verified
    assert v.authorize_target_for_scan(target, org_id=target.org_id, now=NOW) is None


@pytest.mark.asyncio
async def test_wrong_token_and_missing_record_fail(monkeypatch):
    target = make_target()
    issued = await issue(target, monkeypatch)

    async def other_token(name):
        return ["orchestrasec-verify=someone-elses-token"]

    assert (
        await v.check_challenge(fake_db(), target, now=NOW, fetcher=other_token)
        == v.CheckResult.token_mismatch
    )
    assert target.verification_status == VerificationStatus.pending

    async def nothing(name):
        return []

    later = NOW + timedelta(minutes=1)
    assert (
        await v.check_challenge(fake_db(), target, now=later, fetcher=nothing)
        == v.CheckResult.record_not_found
    )
    assert issued.challenge.attempts == 2
    assert issued.challenge.last_result == "record_not_found"


@pytest.mark.asyncio
async def test_bare_token_without_prefix_is_not_accepted(monkeypatch):
    target = make_target()
    issued = await issue(target, monkeypatch)

    async def bare(name):
        return [issued.token]

    result = await v.check_challenge(fake_db(), target, now=NOW, fetcher=bare)
    assert result == v.CheckResult.token_mismatch


@pytest.mark.asyncio
async def test_expired_challenge_cannot_verify(monkeypatch):
    target = make_target()
    issued = await issue(target, monkeypatch)
    fetcher = AsyncMock(return_value=[f"orchestrasec-verify={issued.token}"])

    result = await v.check_challenge(
        fake_db(), target, now=NOW + timedelta(hours=73), fetcher=fetcher
    )
    assert result == v.CheckResult.challenge_expired
    assert issued.challenge.status == ChallengeStatus.expired
    assert target.verification_status == VerificationStatus.unverified
    fetcher.assert_not_called()


@pytest.mark.asyncio
async def test_checks_are_rate_limited_without_querying_dns(monkeypatch):
    target = make_target()
    await issue(target, monkeypatch)
    fetcher = AsyncMock(return_value=[])
    await v.check_challenge(fake_db(), target, now=NOW, fetcher=fetcher)
    result = await v.check_challenge(
        fake_db(), target, now=NOW + timedelta(seconds=2), fetcher=fetcher
    )
    assert result == v.CheckResult.rate_limited
    assert fetcher.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["dns_timeout", "dns_error"])
async def test_dns_failures_do_not_change_state(monkeypatch, code):
    target = make_target()
    issued = await issue(target, monkeypatch)

    async def failing(name):
        raise v.DnsLookupError(code)

    result = await v.check_challenge(fake_db(), target, now=NOW, fetcher=failing)
    assert result.value == code
    assert target.verification_status == VerificationStatus.pending
    assert issued.challenge.status == ChallengeStatus.pending


@pytest.mark.asyncio
async def test_recheck_failure_revokes_previous_verification(monkeypatch):
    target = make_target()
    issued = await issue(target, monkeypatch)
    good = AsyncMock(return_value=[f"orchestrasec-verify={issued.token}"])
    await v.check_challenge(fake_db(), target, now=NOW, fetcher=good)
    assert target.verification_status == VerificationStatus.verified

    gone = AsyncMock(return_value=[])
    later = NOW + timedelta(days=1)
    result = await v.check_challenge(fake_db(), target, now=later, fetcher=gone)
    assert result == v.CheckResult.record_not_found
    assert target.verification_status == VerificationStatus.pending
    assert target.verified_domain is None
    assert issued.challenge.status == ChallengeStatus.pending
    assert issued.challenge.expires_at == later + timedelta(hours=72)


@pytest.mark.asyncio
async def test_check_without_challenge(no_live_challenge):
    result = await v.check_challenge(fake_db(), make_target(), now=NOW, fetcher=AsyncMock())
    assert result == v.CheckResult.no_challenge


def verified_target(**kw) -> ScanTarget:
    params = {
        "verification_status": VerificationStatus.verified,
        "verified_domain": "app.example.com",
        "verified_at": NOW,
        "verification_expires_at": NOW + timedelta(days=30),
    }
    params.update(kw)
    return make_target(**params)


def test_authorization_gate_denials():
    t = verified_target()
    assert v.authorize_target_for_scan(t, org_id=t.org_id, now=NOW) is None
    # another tenant can never use this target's verification
    assert (
        v.authorize_target_for_scan(t, org_id=uuid4(), now=NOW)
        == v.AuthorizationDenied.invalid_target
    )
    unverified = make_target()
    assert (
        v.authorize_target_for_scan(unverified, org_id=unverified.org_id, now=NOW)
        == v.AuthorizationDenied.unverified
    )
    # a status flag alone is not enough: the domain binding must exist and match
    flag_only = make_target(verification_status=VerificationStatus.verified)
    assert (
        v.authorize_target_for_scan(flag_only, org_id=flag_only.org_id, now=NOW)
        == v.AuthorizationDenied.unverified
    )
    other_domain = verified_target(verified_domain="other.example.com")
    assert (
        v.authorize_target_for_scan(other_domain, org_id=other_domain.org_id, now=NOW)
        == v.AuthorizationDenied.domain_mismatch
    )
    assert (
        v.authorize_target_for_scan(t, org_id=t.org_id, now=NOW + timedelta(days=31))
        == v.AuthorizationDenied.expired
    )


def test_can_scan_unverified_target_is_false():
    assert v.can_scan_unverified_target() is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (dns.resolver.NXDOMAIN(), []),
        (dns.resolver.NoAnswer(), []),
        (dns.exception.Timeout(), "dns_timeout"),
        (dns.resolver.NoNameservers(), "dns_error"),
    ],
)
async def test_fetch_txt_values_maps_dns_errors(monkeypatch, exc, expected):
    async def fake_resolve(self, name, rdtype, lifetime=None):
        assert rdtype == "TXT"
        assert lifetime == 5.0
        raise exc

    monkeypatch.setattr("dns.asyncresolver.Resolver.resolve", fake_resolve)
    if isinstance(expected, list):
        assert await v.fetch_txt_values("_orchestrasec.example.com") == expected
    else:
        with pytest.raises(v.DnsLookupError) as err:
            await v.fetch_txt_values("_orchestrasec.example.com")
        assert err.value.code == expected
