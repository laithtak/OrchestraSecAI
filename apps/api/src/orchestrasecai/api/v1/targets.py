from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.api.deps import require_perm
from orchestrasecai.api.schemas import TargetCreate, TargetOut, UserOut, VerificationOut
from orchestrasecai.domain.services.audit import write_audit_log
from orchestrasecai.domain.verification import (
    CheckResult,
    TxtFetcher,
    authorize_target_for_scan,
    check_challenge,
    issue_challenge,
    latest_challenge,
    record_name,
    record_value,
    target_hostname,
    verification_instructions,
)
from orchestrasecai.observability.metrics import domain_verification_checks_total
from orchestrasecai.persistence.session import get_db
from orchestrasecai.persistence.tables.core import (
    DomainVerificationChallenge,
    Project,
    ScanTarget,
    VerificationStatus,
)
from orchestrasecai.security.scope import DEFAULT_PORTS, ScopeError, validate_target_definition
from orchestrasecai.security.ssrf import SSRFError, resolve_public_addresses

router = APIRouter(prefix="/targets", tags=["targets"])


def get_txt_fetcher() -> TxtFetcher | None:
    """Dependency seam so tests can substitute DNS; None uses the real resolver."""
    return None


def _now() -> datetime:
    return datetime.now(UTC)


def _target_out(t: ScanTarget) -> TargetOut:
    return TargetOut(
        id=t.id,
        project_id=t.project_id,
        base_url=t.base_url,
        allowed_hosts=list(t.allowed_hosts or []),
        verification_status=t.verification_status.value,
        verified_domain=t.verified_domain,
        verified_at=t.verified_at,
        verification_expires_at=t.verification_expires_at,
        scannable=authorize_target_for_scan(t, org_id=t.org_id, now=_now()) is None,
    )


def _verification_out(
    t: ScanTarget,
    challenge: DomainVerificationChallenge | None,
    *,
    token: str | None = None,
    check_result: CheckResult | None = None,
) -> VerificationOut:
    domain = target_hostname(t.base_url) or ""
    info = verification_instructions(domain)
    return VerificationOut(
        target_id=t.id,
        verification_status=t.verification_status.value,
        verified_domain=t.verified_domain,
        verified_at=t.verified_at,
        verification_expires_at=t.verification_expires_at,
        domain=domain,
        record_name=record_name(domain),
        record_value=record_value(token) if token else None,
        token_hint=challenge.token_hint if challenge else None,
        challenge_status=challenge.status.value if challenge else None,
        challenge_expires_at=challenge.expires_at if challenge else None,
        attempts=challenge.attempts if challenge else 0,
        last_checked_at=challenge.last_checked_at if challenge else None,
        last_result=challenge.last_result if challenge else None,
        check_result=check_result.value if check_result else None,
        message=info["message"],
    )


async def _get_owned_target(db: AsyncSession, target_id: UUID, user: UserOut) -> ScanTarget:
    t = await db.get(ScanTarget, target_id)
    if not t or t.org_id != user.org_id:
        raise HTTPException(404, "Target not found")
    return t


@router.get("", response_model=list[TargetOut])
async def list_targets(
    user: UserOut = Depends(require_perm("targets:read")),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(
        select(ScanTarget)
        .where(ScanTarget.org_id == user.org_id)
        .order_by(ScanTarget.created_at.desc())
    )
    return [_target_out(t) for t in r.scalars().all()]


@router.post("", response_model=TargetOut, status_code=201)
async def create_target(
    body: TargetCreate,
    request: Request,
    user: UserOut = Depends(require_perm("targets:write")),
    db: AsyncSession = Depends(get_db),
):
    proj = await db.get(Project, body.project_id)
    if not proj or proj.org_id != user.org_id:
        raise HTTPException(404, "Project not found")
    try:
        scope = validate_target_definition(body.base_url, body.allowed_hosts)
    except ScopeError as e:
        raise HTTPException(400, str(e)) from e
    scheme = scope.base_url.split(":", 1)[0]
    try:
        await resolve_public_addresses(scope.hostname, DEFAULT_PORTS[scheme])
    except SSRFError as e:
        raise HTTPException(400, str(e)) from e

    t = ScanTarget(
        org_id=user.org_id,
        project_id=body.project_id,
        base_url=scope.base_url,
        allowed_hosts=sorted(scope.hosts - {scope.hostname}),
        verification_status=VerificationStatus.unverified,
    )
    db.add(t)
    await db.flush()
    request.state.audit_record = {
        "org_id": user.org_id,
        "user_id": user.id,
        "action": "target.create",
        "resource_type": "target",
        "resource_id": str(t.id),
        "metadata": {"hostname": scope.hostname},
    }
    return _target_out(t)


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(
    target_id: UUID,
    user: UserOut = Depends(require_perm("targets:read")),
    db: AsyncSession = Depends(get_db),
):
    return _target_out(await _get_owned_target(db, target_id, user))


@router.get("/{target_id}/verification", response_model=VerificationOut)
async def get_target_verification(
    target_id: UUID,
    user: UserOut = Depends(require_perm("targets:read")),
    db: AsyncSession = Depends(get_db),
):
    t = await _get_owned_target(db, target_id, user)
    if not target_hostname(t.base_url):
        raise HTTPException(400, "Target has no valid hostname")
    return _verification_out(t, await latest_challenge(db, t))


@router.post("/{target_id}/verification/challenge", response_model=VerificationOut)
async def issue_verification_challenge(
    target_id: UUID,
    user: UserOut = Depends(require_perm("targets:write")),
    db: AsyncSession = Depends(get_db),
):
    """Issue (or rotate) a DNS TXT challenge. Rotation revokes existing verification."""
    t = await _get_owned_target(db, target_id, user)
    try:
        issued = await issue_challenge(db, t, user_id=user.id, now=_now())
    except ScopeError as e:
        raise HTTPException(400, str(e)) from e
    await write_audit_log(
        db,
        org_id=user.org_id,
        user_id=user.id,
        action="target.verification_challenge_issued",
        resource_type="target",
        resource_id=str(t.id),
        metadata={"domain": issued.challenge.domain, "challenge_id": str(issued.challenge.id)},
    )
    return _verification_out(t, issued.challenge, token=issued.token)


@router.post("/{target_id}/verify", response_model=VerificationOut)
async def verify_target(
    target_id: UUID,
    user: UserOut = Depends(require_perm("targets:write")),
    db: AsyncSession = Depends(get_db),
    fetcher: TxtFetcher | None = Depends(get_txt_fetcher),
):
    t = await _get_owned_target(db, target_id, user)
    if not target_hostname(t.base_url):
        raise HTTPException(400, "Target has no valid hostname")
    result = await check_challenge(db, t, now=_now(), fetcher=fetcher)
    domain_verification_checks_total.labels(result=result.value).inc()
    if result == CheckResult.no_challenge:
        raise HTTPException(409, "No active verification challenge; issue one first")
    if result == CheckResult.rate_limited:
        raise HTTPException(429, "Verification was checked too recently; retry shortly")
    await write_audit_log(
        db,
        org_id=user.org_id,
        user_id=user.id,
        action="target.verification_check",
        resource_type="target",
        resource_id=str(t.id),
        metadata={"result": result.value, "status": t.verification_status.value},
    )
    return _verification_out(t, await latest_challenge(db, t), check_result=result)
