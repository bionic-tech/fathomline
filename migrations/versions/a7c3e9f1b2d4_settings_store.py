"""settings store — in-app runtime settings overrides + version (ADR-038)

Revision ID: a7c3e9f1b2d4
Revises: 55dee382f31a
Create Date: 2026-06-19 13:00:00.000000

Adds the runtime settings store tables: ``settings_override`` (one row per in-app override of a
:class:`Settings` field, plus free-form named secrets; secret values Fernet-encrypted at rest) and
``settings_version`` (a single-row monotonic counter bumped on each mutation for cross-worker live
reload). Portable DDL (PostgreSQL + SQLite). Behaviour-preserving: with no rows the effective
settings are exactly the env-seeded base. Chained off the ai-suite merge head ``55dee382f31a``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a7c3e9f1b2d4"
down_revision: str | None = "55dee382f31a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "settings_override",
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("is_secret", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "settings_version",
        sa.Column("id", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("settings_version")
    op.drop_table("settings_override")
