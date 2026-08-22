"""CSP violation reports table (CYBER-14)

Revision ID: i3j4k5l6m7n8
Revises: h2i3j4k5l6m7
Create Date: 2026-08-22 12:00:00.000000

Browser-standard CSP violation reports collected at POST /api/csp-report.
Linked to monitored sites when the report's document-uri origin matches;
NULL site_id for reports from unmonitored origins.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "i3j4k5l6m7n8"
down_revision: str | Sequence[str] | None = "h2i3j4k5l6m7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "csp_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=True),
        sa.Column("document_uri", sa.String(length=2048), nullable=False),
        sa.Column("violated_directive", sa.String(length=512), nullable=False),
        sa.Column("effective_directive", sa.String(length=512), nullable=True),
        sa.Column("blocked_uri", sa.String(length=2048), nullable=True),
        sa.Column("original_policy", sa.Text(), nullable=True),
        sa.Column("referrer", sa.String(length=2048), nullable=True),
        sa.Column("source_file", sa.String(length=2048), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("column_number", sa.Integer(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("raw_report", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_csp_reports_site_id", "csp_reports", ["site_id"])
    op.create_index("ix_csp_reports_site_created", "csp_reports", ["site_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_csp_reports_site_created", table_name="csp_reports")
    op.drop_index("ix_csp_reports_site_id", table_name="csp_reports")
    op.drop_table("csp_reports")
