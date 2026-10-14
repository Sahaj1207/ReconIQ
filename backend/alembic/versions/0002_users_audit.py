"""Users, audit log and investigation ownership

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-14
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(36), nullable=True),
        sa.Column("actor_email", sa.String(320), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=True),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("ip", sa.String(64), nullable=True),
    )
    for col in ("created_at", "actor_id", "action"):
        op.create_index(f"ix_audit_events_{col}", "audit_events", [col])
    with op.batch_alter_table("investigations") as batch:
        batch.add_column(sa.Column("owner_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("owner_email", sa.String(320), nullable=True))
        batch.create_index("ix_investigations_owner_id", ["owner_id"])


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch:
        batch.drop_index("ix_investigations_owner_id")
        batch.drop_column("owner_email")
        batch.drop_column("owner_id")
    op.drop_table("audit_events")
    op.drop_table("users")
