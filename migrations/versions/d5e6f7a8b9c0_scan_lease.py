"""scan_lease — scan concurrency coordinator ledger (ADR-036)

Revision ID: d5e6f7a8b9c0
Revises: b4d7e9f2a1c5
Create Date: 2026-06-19 00:00:00.000000

Adds the ``scan_lease`` table behind the scan concurrency coordinator (ADR-036): active/released/
expired leases + deferred-scan advisories. Portable DDL (PostgreSQL + SQLite). Behaviour-preserving:
nothing reads or writes it unless ``scan_coordinator_enabled`` is set. Chained off ``b4d7e9f2a1c5``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5e6f7a8b9c0"
down_revision: str | None = "b4d7e9f2a1c5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_lease",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("host.id"), nullable=False),
        sa.Column("is_heavy", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("blocking_host_id", sa.BigInteger(), nullable=True),
        sa.Column("retry_after_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "granted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_lease_status_heavy", "scan_lease", ["status", "is_heavy"])
    op.create_index("ix_scan_lease_host_id", "scan_lease", ["host_id"])
    op.create_index("ix_scan_lease_granted_at", "scan_lease", ["granted_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_lease_granted_at", table_name="scan_lease")
    op.drop_index("ix_scan_lease_host_id", table_name="scan_lease")
    op.drop_index("ix_scan_lease_status_heavy", table_name="scan_lease")
    op.drop_table("scan_lease")
