"""auth rbac schema

Revision ID: b7e2c1a4d9f0
Revises: 3a48eed79c3c
Create Date: 2026-06-05 18:30:00.000000

Human auth + RBAC tables (ADD 13 §§1-3, ADD 03 §2) chained linearly off the catalogue
baseline ``3a48eed79c3c`` — one head, no branch. All types are portable (String / Integer /
DateTime(timezone=True) / Boolean) so the SQLite test suite stays green alongside PostgreSQL;
no Postgres-only DDL is needed for these tables (unlike fs_entry partitioning).

Also adds ``volume.kind`` (data|system) with a ``'data'`` server default so the root-volume
vs data-volume privilege split is representable in scope/capability gating (AR-011).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b7e2c1a4d9f0"
down_revision: str | None = "3a48eed79c3c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "volume",
        sa.Column("kind", sa.String(length=16), nullable=False, server_default="data"),
    )

    op.create_table(
        "auth_user",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "subject", name="uq_auth_user_source_subject"),
    )

    op.create_table(
        "auth_role_assignment",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("scope_kind", sa.String(length=16), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("volume_id", sa.Integer(), nullable=True),
        sa.Column("granted_by", sa.String(length=255), nullable=True),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["auth_user.id"]),
        sa.ForeignKeyConstraint(["host_id"], ["host.id"]),
        sa.ForeignKeyConstraint(["volume_id"], ["volume.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_auth_role_assignment_user_id"),
        "auth_role_assignment",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "auth_session",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mfa_authenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["auth_user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_auth_session_user_id"), "auth_session", ["user_id"], unique=False)

    op.create_table(
        "auth_mfa_enrollment",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=16), nullable=False),
        sa.Column("secret_ref", sa.String(length=255), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["auth_user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_auth_mfa_enrollment_user_id"),
        "auth_mfa_enrollment",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "auth_identity_binding",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("group_claim", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_claim"),
    )


def downgrade() -> None:
    op.drop_table("auth_identity_binding")
    op.drop_index(op.f("ix_auth_mfa_enrollment_user_id"), table_name="auth_mfa_enrollment")
    op.drop_table("auth_mfa_enrollment")
    op.drop_index(op.f("ix_auth_session_user_id"), table_name="auth_session")
    op.drop_table("auth_session")
    op.drop_index(op.f("ix_auth_role_assignment_user_id"), table_name="auth_role_assignment")
    op.drop_table("auth_role_assignment")
    op.drop_table("auth_user")
    op.drop_column("volume", "kind")
