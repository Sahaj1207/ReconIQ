"""Initial schema: investigations

Revision ID: 0001
Revises:
Create Date: 2026-10-14
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_name", sa.String(255), nullable=True),
        sa.Column("input_preview", sa.Text(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("classification", sa.String(64), nullable=False),
        sa.Column("ioc_count", sa.Integer(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
    )
    for col in ("created_at", "source_type", "score", "severity", "classification"):
        op.create_index(f"ix_investigations_{col}", "investigations", [col])


def downgrade() -> None:
    op.drop_table("investigations")
