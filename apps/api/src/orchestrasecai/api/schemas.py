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
    base_url: str
    allowed_hosts: list[str] = Field(default_factory=list)


class TargetOut(BaseModel):
    id: UUID
    project_id: UUID
    base_url: str
    allowed_hosts: list[str]
    verification_status: str

    model_config = {"from_attributes": True}


class PolicyCreate(BaseModel):
    name: str = "Default"
    max_pages: int = 50
    max_depth: int = 3
    requests_per_second: float = 2.0
    respect_robots_txt: bool = True
    user_agent: str | None = None
    blocked_path_patterns: list[str] = Field(default_factory=list)


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
    plugin_ids: list[str] = Field(default_factory=lambda: ["header", "cookie", "tls", "disclosure"])


class ScanOut(BaseModel):
    id: UUID
    status: str
    created_at: datetime
    stats: dict = Field(default_factory=dict)
    links: dict | None = None

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: UUID
    plugin_id: str
    severity: str
    title: str
    description: str
    location: dict
    status: str

    model_config = {"from_attributes": True}


class FindingPatch(BaseModel):
    status: str


class Problem(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str | None = None
