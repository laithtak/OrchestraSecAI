from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: UUID
    email: str
    role: str
    org_id: UUID

    model_config = {"from_attributes": True}


class MeResponse(BaseModel):
    user: UserOut
    org: dict


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None


class ProjectOut(BaseModel):
    id: UUID
    name: str
    description: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class TargetCreate(BaseModel):
    project_id: UUID
    base_url: str = Field(..., min_length=8, max_length=2048)
    allowed_hosts: list[str] = Field(default_factory=list, max_length=20)


class TargetOut(BaseModel):
    id: UUID
    project_id: UUID
    base_url: str
    allowed_hosts: list[str]
    verification_status: str
    verified_domain: str | None = None
    verified_at: datetime | None = None
    verification_expires_at: datetime | None = None
    scannable: bool = False

    model_config = {"from_attributes": True}


class VerificationOut(BaseModel):
    target_id: UUID
    verification_status: str
    verified_domain: str | None = None
    verified_at: datetime | None = None
    verification_expires_at: datetime | None = None
    method: str = "dns_txt"
    domain: str
    record_name: str
    record_type: str = "TXT"
    # Plaintext record value is only returned when a challenge is issued or rotated.
    record_value: str | None = None
    token_hint: str | None = None
    challenge_status: str | None = None
    challenge_expires_at: datetime | None = None
    attempts: int = 0
    last_checked_at: datetime | None = None
    last_result: str | None = None
    check_result: str | None = None
    message: str


class PolicyCreate(BaseModel):
    name: str = Field("Default", min_length=1, max_length=255)
    max_pages: int = Field(50, ge=1, le=500)
    max_depth: int = Field(3, ge=0, le=10)
    requests_per_second: float = Field(2.0, gt=0, le=10)
    respect_robots_txt: bool = True
    user_agent: str | None = Field(None, max_length=255)
    blocked_path_patterns: list[str] = Field(default_factory=list, max_length=50)


class PolicyOut(BaseModel):
    id: UUID
    name: str
    max_pages: int
    max_depth: int
    requests_per_second: float
    respect_robots_txt: bool

    model_config = {"from_attributes": True}


class ScanCreate(BaseModel):
    scan_target_id: UUID
    scan_policy_id: UUID
    mission: str = Field(..., min_length=10, max_length=4000)
    plugin_ids: list[str] | None = Field(
        default=None,
        description="Deprecated — agent selects plugins dynamically",
    )
    allow_active_probes: bool = Field(
        default=False,
        description=(
            "Explicit, audited opt-in to allowlisted active probes. Requires the "
            "scans:active permission and ACTIVE_PROBES_ALLOWED on the deployment."
        ),
    )


class AgentSessionOut(BaseModel):
    mission: str
    status: str
    iteration: int
    max_iterations: int
    trace: list = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)


class ScanOut(BaseModel):
    id: UUID
    status: str
    mission: str | None = None
    created_at: datetime
    stats: dict = Field(default_factory=dict)
    links: dict | None = None
    target_id: UUID | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    attempts: int = 0
    active_probes_enabled: bool = False

    model_config = {"from_attributes": True}


class EvidenceOut(BaseModel):
    type: str
    payload: dict | list | str | None


class FindingOut(BaseModel):
    id: UUID
    plugin_id: str
    severity: str
    title: str
    description: str
    location: dict
    status: str
    scan_id: UUID | None = None
    fingerprint: str | None = None
    remediation: str | None = None
    check_id: str | None = None
    check_version: str | None = None
    created_at: datetime | None = None
    evidence: list[EvidenceOut] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class FindingPatch(BaseModel):
    status: str


class Problem(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str | None = None
