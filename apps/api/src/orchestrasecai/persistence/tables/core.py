import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from orchestrasecai.persistence.base import Base


def _str_enum(enum_cls: type[enum.Enum]) -> Enum:
    # Migrations store enum columns as VARCHAR; a native PG ENUM binding would emit
    # casts to types that do not exist in the deployed schema.
    return Enum(enum_cls, native_enum=False, length=50, create_constraint=False)


class PlanType(str, enum.Enum):
    free = "free"
    pro = "pro"


class UserRole(str, enum.Enum):
    owner = "owner"
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class VerificationStatus(str, enum.Enum):
    unverified = "unverified"
    pending = "pending"
    verified = "verified"


class ScanStatus(str, enum.Enum):
    """Durable scan lifecycle. Legal transitions live in domain/scan_lifecycle.py."""

    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    timed_out = "timed_out"


class ChallengeStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    expired = "expired"
    superseded = "superseded"


class AgentSessionStatus(str, enum.Enum):
    running = "running"
    complete = "complete"
    failed = "failed"
    max_iterations = "max_iterations"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"


class FindingStatus(str, enum.Enum):
    open = "open"
    accepted_risk = "accepted_risk"
    false_positive = "false_positive"


class ReportFormat(str, enum.Enum):
    json = "json"
    html = "html"
    pdf = "pdf"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    plan: Mapped[PlanType] = mapped_column(_str_enum(PlanType), default=PlanType.free)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    role: Mapped[UserRole] = mapped_column(_str_enum(UserRole), default=UserRole.analyst)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False)
    base_url: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_hosts: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    verification_status: Mapped[VerificationStatus] = mapped_column(
        _str_enum(VerificationStatus), default=VerificationStatus.unverified, nullable=False
    )
    # Ownership binding: set only by a successful DNS challenge for this org + target.
    verified_domain: Mapped[str | None] = mapped_column(String(253), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DomainVerificationChallenge(Base):
    __tablename__ = "domain_verification_challenges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_targets.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    method: Mapped[str] = mapped_column(String(20), nullable=False, default="dns_txt")
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hint: Mapped[str] = mapped_column(String(12), nullable=False)
    status: Mapped[ChallengeStatus] = mapped_column(
        _str_enum(ChallengeStatus), nullable=False, default=ChallengeStatus.pending
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_result: Mapped[str | None] = mapped_column(String(50), nullable=True)


class ScanPolicy(Base):
    __tablename__ = "scan_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), default="Default")
    max_pages: Mapped[int] = mapped_column(Integer, default=50)
    max_depth: Mapped[int] = mapped_column(Integer, default=3)
    requests_per_second: Mapped[float] = mapped_column(Numeric(5, 2), default=2.0)
    respect_robots_txt: Mapped[bool] = mapped_column(Boolean, default=True)
    user_agent: Mapped[str] = mapped_column(
        String(255), default="OrchestraSecAI-Scanner/0.1 (+https://orchestrasec.ai)"
    )
    blocked_path_patterns: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    scan_target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)
    scan_policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_policies.id"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        _str_enum(ScanStatus), default=ScanStatus.queued, nullable=False
    )
    plugin_ids: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True, default=list)
    mission: Mapped[str] = mapped_column(Text, nullable=False, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    worker_job_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    active_probes_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    target: Mapped["ScanTarget"] = relationship()
    policy: Mapped["ScanPolicy"] = relationship()
    agent_session: Mapped["AgentSession | None"] = relationship(back_populates="scan", uselist=False)


class AgentSession(Base):
    __tablename__ = "agent_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), unique=True, nullable=False
    )
    mission: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[AgentSessionStatus] = mapped_column(
        _str_enum(AgentSessionStatus), default=AgentSessionStatus.running
    )
    iteration: Mapped[int] = mapped_column(Integer, default=0)
    max_iterations: Mapped[int] = mapped_column(Integer, nullable=False)
    trace: Mapped[list] = mapped_column(JSONB, default=list)
    summary: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="agent_session")


class CrawlPage(Base):
    __tablename__ = "crawl_pages"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_crawl_pages_scan_url"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    final_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    parent_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    headers: Mapped[dict] = mapped_column(JSONB, default=dict)
    body_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanCheckRun(Base):
    __tablename__ = "scan_check_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    check_plugin_id: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    plugin_id: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[Severity] = mapped_column(_str_enum(Severity), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    location: Mapped[dict] = mapped_column(JSONB, default=dict)
    cvss_estimate: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    check_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    check_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    status: Mapped[FindingStatus] = mapped_column(_str_enum(FindingStatus), default=FindingStatus.open)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    evidence: Mapped[list["FindingEvidence"]] = relationship(back_populates="finding")


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)

    finding: Mapped["Finding"] = relationship(back_populates="evidence")


class AiAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(50), nullable=False)
    input_token_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_token_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("scan_id", "format", "version", name="uq_reports_scan_format_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    format: Mapped[ReportFormat] = mapped_column(_str_enum(ReportFormat), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    generator: Mapped[str | None] = mapped_column(String(50), nullable=True)
    content_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
