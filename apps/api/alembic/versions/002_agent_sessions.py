"""agent sessions and scan mission

Revision ID: 002
Revises: 001
Create Date: 2026-06-22

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("mission", sa.Text(), nullable=True))
    op.execute("UPDATE scans SET mission = 'Legacy scan (no mission)' WHERE mission IS NULL")
    op.alter_column("scans", "mission", nullable=False)

    op.create_table(
        "agent_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("mission", sa.Text(), nullable=False),
        sa.Column("status", sa.String(50), server_default="running", nullable=False),
        sa.Column("iteration", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_iterations", sa.Integer(), nullable=False),
        sa.Column("trace", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("summary", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", name="uq_agent_sessions_scan_id"),
    )
    op.create_index("ix_agent_sessions_scan_id", "agent_sessions", ["scan_id"])

    op.execute(
        "UPDATE scans SET status = 'agent_running' WHERE status IN ('crawling', 'scanning')"
    )


def downgrade() -> None:
    op.drop_index("ix_agent_sessions_scan_id", table_name="agent_sessions")
    op.drop_table("agent_sessions")
    op.drop_column("scans", "mission")
    op.execute(
        "UPDATE scans SET status = 'scanning' WHERE status = 'agent_running'"
    )
