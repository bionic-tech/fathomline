"""notification — in-app Notification Center store (ADR-031)

Revision ID: e1f2a3b4c5d6
Revises: b4d7e9f2a1c5
Create Date: 2026-06-19 00:00:00.000000

Adds the ``notification`` table behind the in-app Notification Center ("bell", ADR-031). Portable
DDL (PostgreSQL + SQLite). Behaviour-preserving: nothing reads or writes it unless
``notifications_enabled`` is set. Chained off ``b4d7e9f2a1c5`` (shares that parent with the
concierge + scan-coordinator migrations on their branches — to be linearised when those land).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e1f2a3b4c5d6"
down_revision: str | None = "b4d7e9f2a1c5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="info"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("volume_id", sa.Integer(), nullable=True),
        sa.Column("dedup_key", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_notification_host_id", "notification", ["host_id"])
    op.create_index("ix_notification_created_at", "notification", ["created_at"])
    op.create_index("ix_notification_read_at", "notification", ["read_at"])
    op.create_index("ix_notification_dedup", "notification", ["dedup_key"])


def downgrade() -> None:
    op.drop_index("ix_notification_dedup", table_name="notification")
    op.drop_index("ix_notification_read_at", table_name="notification")
    op.drop_index("ix_notification_created_at", table_name="notification")
    op.drop_index("ix_notification_host_id", table_name="notification")
    op.drop_table("notification")
