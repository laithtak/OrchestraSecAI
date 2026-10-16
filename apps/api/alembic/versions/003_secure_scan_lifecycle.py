"""secure scan lifecycle: domain verification challenges, lifecycle state, findings metadata

Revision ID: 003
Revises: 002
Create Date: 2026-10-12

Security-relevant data changes (intentional, documented in docs/scan-lifecycle.md):

* Targets previously marked ``verified``/``pending`` were verified with a deterministic,
  non-expiring token (``verify-<target_id>``) and carry no binding to a verified domain.
  They are reset to ``unverified`` and must complete the new DNS TXT challenge.
* Legacy in-flight scan states (crawling/scanning/agent_running/analyzing) map to
  ``running``; the stale-scan reaper then resolves them (timed_out / failed) because no
  worker holds a lease for them.
* Duplicate report rows are renumbered so (scan_id, format, version) can be unique.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCAN_STATUSES = ("queued", "running", "completed", "failed", "cancelled", "timed_out")


def upgrade() -> None:
    # --- target ownership verification -------------------------------------------------
    op.add_column("scan_targets", sa.Column("verified_domain", sa.String(253), nullable=True))
    op.add_column(
        "scan_targets", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "scan_targets",
        sa.Column("verification_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "UPDATE scan_targets SET verification_status = 'unverified' "
        "WHERE verification_status IS NULL OR verification_status <> 'unverified'"
    )
    op.alter_column(
        "scan_targets", "verification_status", nullable=False, server_default="unverified"
    )
    op.create_check_constraint(
        "ck_scan_targets_verification_status",
        "scan_targets",
        "verification_status IN ('unverified', 'pending', 'verified')",
    )
    op.create_check_constraint(
        "ck_scan_targets_verified_binding",
        "scan_targets",
        "verification_status <> 'verified' OR "
        "(verified_domain IS NOT NULL AND verified_at IS NOT NULL "
        "AND verification_expires_at IS NOT NULL)",
    )
    op.create_index("ix_scan_targets_org_id", "scan_targets", ["org_id"])

    op.create_table(
        "domain_verification_challenges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("method", sa.String(20), nullable=False, server_default="dns_txt"),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("token_hint", sa.String(12), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_result", sa.String(50), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'verified', 'expired', 'superseded')",
            name="ck_domain_challenges_status",
        ),
        sa.CheckConstraint("method IN ('dns_txt')", name="ck_domain_challenges_method"),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_domain_challenges_token_hash"),
    )
    op.create_index(
        "ix_domain_challenges_target_id", "domain_verification_challenges", ["target_id"]
    )
    # At most one live (pending or verified) challenge per target.
    op.create_index(
        "uq_domain_challenges_live_target",
        "domain_verification_challenges",
        ["target_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'verified')"),
    )

    # --- scan lifecycle --------------------------------------------------------------
    op.execute(
        "UPDATE scans SET status = 'running' "
        "WHERE status IN ('crawling', 'scanning', 'agent_running', 'analyzing')"
    )
    op.execute("UPDATE scans SET status = 'queued' WHERE status IS NULL")
    op.alter_column("scans", "status", nullable=False, server_default="queued")
    op.create_check_constraint(
        "ck_scans_status",
        "scans",
        "status IN (" + ", ".join(f"'{s}'" for s in SCAN_STATUSES) + ")",
    )
    op.add_column("scans", sa.Column("error_code", sa.String(50), nullable=True))
    op.add_column(
        "scans", sa.Column("attempts", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "scans", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("scans", sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scans", sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("scans", sa.Column("worker_job_id", sa.String(100), nullable=True))
    op.add_column(
        "scans",
        sa.Column(
            "active_probes_enabled", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.create_check_constraint("ck_scans_attempts", "scans", "attempts >= 0")

    # --- findings metadata -------------------------------------------------------------
    op.add_column("findings", sa.Column("remediation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("check_id", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("check_version", sa.String(20), nullable=True))
    op.create_index("ix_findings_org_id", "findings", ["org_id"])
    op.create_index("ix_finding_evidence_finding_id", "finding_evidence", ["finding_id"])

    # --- reports and AI analyses -------------------------------------------------------
    op.execute(
        """
        UPDATE reports SET version = numbered.rn
        FROM (
            SELECT id, row_number() OVER (
                PARTITION BY scan_id, format ORDER BY generated_at, id
            ) AS rn
            FROM reports
        ) AS numbered
        WHERE reports.id = numbered.id
        """
    )
    op.add_column("reports", sa.Column("generator", sa.String(50), nullable=True))
    op.add_column("reports", sa.Column("content_sha256", sa.String(64), nullable=True))
    op.create_unique_constraint(
        "uq_reports_scan_format_version", "reports", ["scan_id", "format", "version"]
    )
    op.add_column(
        "ai_analyses",
        sa.Column("status", sa.String(20), nullable=False, server_default="completed"),
    )


def downgrade() -> None:
    op.drop_column("ai_analyses", "status")
    op.drop_constraint("uq_reports_scan_format_version", "reports", type_="unique")
    op.drop_column("reports", "content_sha256")
    op.drop_column("reports", "generator")

    op.drop_index("ix_finding_evidence_finding_id", table_name="finding_evidence")
    op.drop_index("ix_findings_org_id", table_name="findings")
    op.drop_column("findings", "check_version")
    op.drop_column("findings", "check_id")
    op.drop_column("findings", "remediation")

    op.drop_constraint("ck_scans_attempts", "scans", type_="check")
    op.drop_column("scans", "active_probes_enabled")
    op.drop_column("scans", "worker_job_id")
    op.drop_column("scans", "cancel_requested_at")
    op.drop_column("scans", "deadline_at")
    op.drop_column("scans", "lease_expires_at")
    op.drop_column("scans", "attempts")
    op.drop_column("scans", "error_code")
    op.drop_constraint("ck_scans_status", "scans", type_="check")
    op.execute("UPDATE scans SET status = 'agent_running' WHERE status = 'running'")
    op.execute("UPDATE scans SET status = 'failed' WHERE status = 'timed_out'")

    op.drop_index("uq_domain_challenges_live_target", table_name="domain_verification_challenges")
    op.drop_index("ix_domain_challenges_target_id", table_name="domain_verification_challenges")
    op.drop_table("domain_verification_challenges")
    op.drop_index("ix_scan_targets_org_id", table_name="scan_targets")
    op.drop_constraint("ck_scan_targets_verified_binding", "scan_targets", type_="check")
    op.drop_constraint("ck_scan_targets_verification_status", "scan_targets", type_="check")
    op.drop_column("scan_targets", "verification_expires_at")
    op.drop_column("scan_targets", "verified_at")
    op.drop_column("scan_targets", "verified_domain")
