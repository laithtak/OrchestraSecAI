"""Domain ownership verification via DNS TXT challenges.

A challenge is a cryptographically random token bound to one organization, one target
and that target's canonical hostname. Only the SHA-256 hash of the token is stored; the
plaintext is returned once when the challenge is issued (or rotated). The operator
publishes ``orchestrasec-verify=<token>`` as a TXT record at
``_orchestrasec.<hostname>``. A successful check binds ``verified_domain`` on the target;
scans and worker execution require that binding to match the target hostname and to be
unexpired (``authorize_target_for_scan``).
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

import dns.asyncresolver
import dns.exception
import dns.resolver
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.config import get_settings
from orchestrasecai.persistence.tables.core import (
    ChallengeStatus,
    DomainVerificationChallenge,
    ScanTarget,
    VerificationStatus,
)
from orchestrasecai.security.scope import ScopeError, target_scope

RECORD_LABEL = "_orchestrasec"
TXT_VALUE_PREFIX = "orchestrasec-verify="
TOKEN_BYTES = 32
MAX_TXT_VALUES_CONSIDERED = 50


class DnsLookupError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


TxtFetcher = Callable[[str], Awaitable[list[str]]]


class CheckResult(str, enum.Enum):
    verified = "verified"
    record_not_found = "record_not_found"
    token_mismatch = "token_mismatch"
    dns_timeout = "dns_timeout"
    dns_error = "dns_error"
    challenge_expired = "challenge_expired"
    no_challenge = "no_challenge"
    rate_limited = "rate_limited"


class AuthorizationDenied(str, enum.Enum):
    unverified = "target_unverified"
    domain_mismatch = "verification_domain_mismatch"
    expired = "verification_expired"
    invalid_target = "invalid_target"


@dataclass
class IssuedChallenge:
    challenge: DomainVerificationChallenge
    token: str


def record_name(domain: str) -> str:
    return f"{RECORD_LABEL}.{domain}"


def record_value(token: str) -> str:
    return f"{TXT_VALUE_PREFIX}{token}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def target_hostname(base_url: str) -> str | None:
    """Canonical (lower-case, IDNA) hostname of a target, or None if invalid."""
    try:
        return target_scope(base_url, []).hostname
    except ScopeError:
        return None


def verification_instructions(domain: str, token: str | None = None) -> dict:
    return {
        "method": "dns_txt",
        "record_name": record_name(domain),
        "record_type": "TXT",
        "record_value": record_value(token) if token else None,
        "message": (
            "Publish the TXT record, wait for DNS propagation, then run the check. "
            "The token is shown only once; rotate the challenge if it is lost."
        ),
    }


async def fetch_txt_values(name: str) -> list[str]:
    """Narrow TXT lookup for exactly ``name`` with a bounded total lifetime."""
    settings = get_settings()
    resolver = dns.asyncresolver.Resolver()
    if settings.domain_verification_nameserver_list:
        resolver.nameservers = settings.domain_verification_nameserver_list
    timeout = settings.domain_verification_dns_timeout_seconds
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = await resolver.resolve(name, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout as exc:
        raise DnsLookupError(CheckResult.dns_timeout.value) from exc
    except dns.exception.DNSException as exc:
        raise DnsLookupError(CheckResult.dns_error.value) from exc

    values: list[str] = []
    for rdata in answer:
        joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
        values.append(joined)
        if len(values) >= MAX_TXT_VALUES_CONSIDERED:
            break
    return values


def _matches(values: list[str], token_hash: str) -> bool:
    found = False
    for value in values[:MAX_TXT_VALUES_CONSIDERED]:
        candidate = value.strip().strip('"').strip()
        if not candidate.startswith(TXT_VALUE_PREFIX):
            continue
        token = candidate[len(TXT_VALUE_PREFIX) :]
        if len(token) > 128:
            continue
        # Compare every candidate in constant time; do not short-circuit on success.
        if hmac.compare_digest(hash_token(token), token_hash):
            found = True
    return found


async def current_challenge(
    db: AsyncSession, target: ScanTarget, *, for_update: bool = False
) -> DomainVerificationChallenge | None:
    stmt = (
        select(DomainVerificationChallenge)
        .where(
            DomainVerificationChallenge.target_id == target.id,
            DomainVerificationChallenge.org_id == target.org_id,
            DomainVerificationChallenge.status.in_(
                [ChallengeStatus.pending, ChallengeStatus.verified]
            ),
        )
        .order_by(DomainVerificationChallenge.created_at.desc())
        .limit(1)
    )
    if for_update:
        stmt = stmt.with_for_update()
    r = await db.execute(stmt)
    return r.scalar_one_or_none()


async def latest_challenge(
    db: AsyncSession, target: ScanTarget
) -> DomainVerificationChallenge | None:
    r = await db.execute(
        select(DomainVerificationChallenge)
        .where(
            DomainVerificationChallenge.target_id == target.id,
            DomainVerificationChallenge.org_id == target.org_id,
        )
        .order_by(DomainVerificationChallenge.created_at.desc())
        .limit(1)
    )
    return r.scalar_one_or_none()


def _clear_verification(target: ScanTarget, status: VerificationStatus) -> None:
    target.verification_status = status
    target.verified_domain = None
    target.verified_at = None
    target.verification_expires_at = None


async def issue_challenge(
    db: AsyncSession, target: ScanTarget, *, user_id: UUID | None, now: datetime
) -> IssuedChallenge:
    """Create a fresh challenge, superseding any live one (rotation revokes verification)."""
    domain = target_hostname(target.base_url)
    if domain is None:
        raise ScopeError("Target has no valid hostname")

    existing = await current_challenge(db, target, for_update=True)
    if existing is not None:
        existing.status = ChallengeStatus.superseded
        await db.flush()

    token = secrets.token_urlsafe(TOKEN_BYTES)
    settings = get_settings()
    challenge = DomainVerificationChallenge(
        org_id=target.org_id,
        target_id=target.id,
        domain=domain,
        method="dns_txt",
        token_hash=hash_token(token),
        token_hint=token[:6],
        status=ChallengeStatus.pending,
        created_by=user_id,
        created_at=now,
        expires_at=now + timedelta(hours=settings.domain_verification_challenge_ttl_hours),
        attempts=0,
    )
    db.add(challenge)
    _clear_verification(target, VerificationStatus.pending)
    await db.flush()
    return IssuedChallenge(challenge=challenge, token=token)


async def check_challenge(
    db: AsyncSession,
    target: ScanTarget,
    *,
    now: datetime,
    fetcher: TxtFetcher | None = None,
) -> CheckResult:
    """Check DNS for the target's live challenge and update verification state."""
    settings = get_settings()
    challenge = await current_challenge(db, target, for_update=True)
    if challenge is None:
        return CheckResult.no_challenge

    domain = target_hostname(target.base_url)
    if domain is None or domain != challenge.domain:
        challenge.status = ChallengeStatus.superseded
        _clear_verification(target, VerificationStatus.unverified)
        await db.flush()
        return CheckResult.no_challenge

    if challenge.status == ChallengeStatus.pending and challenge.expires_at <= now:
        challenge.status = ChallengeStatus.expired
        challenge.last_result = CheckResult.challenge_expired.value
        _clear_verification(target, VerificationStatus.unverified)
        await db.flush()
        return CheckResult.challenge_expired

    cooldown = timedelta(seconds=settings.domain_verification_check_cooldown_seconds)
    if challenge.last_checked_at is not None and now - challenge.last_checked_at < cooldown:
        return CheckResult.rate_limited

    challenge.attempts += 1
    challenge.last_checked_at = now
    try:
        values = await (fetcher or fetch_txt_values)(record_name(challenge.domain))
    except DnsLookupError as exc:
        # Transient DNS failures never change verification state.
        challenge.last_result = exc.code
        await db.flush()
        return CheckResult(exc.code)

    if _matches(values, challenge.token_hash):
        challenge.status = ChallengeStatus.verified
        challenge.verified_at = now
        challenge.last_result = CheckResult.verified.value
        target.verification_status = VerificationStatus.verified
        target.verified_domain = challenge.domain
        target.verified_at = now
        target.verification_expires_at = now + timedelta(
            days=settings.domain_verification_max_age_days
        )
        await db.flush()
        return CheckResult.verified

    result = CheckResult.token_mismatch if values else CheckResult.record_not_found
    challenge.last_result = result.value
    if challenge.status == ChallengeStatus.verified:
        # The proof was removed from DNS: revoke and give a fresh window to restore it.
        challenge.status = ChallengeStatus.pending
        challenge.verified_at = None
        challenge.expires_at = now + timedelta(
            hours=settings.domain_verification_challenge_ttl_hours
        )
        _clear_verification(target, VerificationStatus.pending)
    await db.flush()
    return result


def authorize_target_for_scan(
    target: ScanTarget, *, org_id: UUID, now: datetime
) -> AuthorizationDenied | None:
    """Deterministic gate shared by the API and the worker. ``None`` means authorized."""
    if target.org_id != org_id:
        return AuthorizationDenied.invalid_target
    hostname = target_hostname(target.base_url)
    if hostname is None:
        return AuthorizationDenied.invalid_target
    if (
        target.verification_status != VerificationStatus.verified
        or target.verified_domain is None
        or target.verified_at is None
    ):
        return AuthorizationDenied.unverified
    if target.verified_domain != hostname:
        return AuthorizationDenied.domain_mismatch
    if target.verification_expires_at is None or target.verification_expires_at <= now:
        return AuthorizationDenied.expired
    return None


def can_scan_unverified_target() -> bool:
    """There is no bypass: unverified targets are never scannable."""
    return False
