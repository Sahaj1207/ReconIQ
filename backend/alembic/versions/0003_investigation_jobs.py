"""Background investigation jobs with per-stage progress

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-14
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_name", sa.String(255), nullable=True),
        sa.Column("stages", sa.JSON(), nullable=False),
        sa.Column("current_stage", sa.String(64), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("investigation_id", sa.String(36), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("owner_id", sa.String(36), nullable=True),
    )
    for col in ("created_at", "status", "owner_id"):
        op.create_index(f"ix_investigation_jobs_{col}", "investigation_jobs", [col])


def downgrade() -> None:
    op.drop_table("investigation_jobs")
