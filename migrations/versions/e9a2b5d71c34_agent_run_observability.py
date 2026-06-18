"""agent_run table — per-run scan outcome for fleet observability

Revision ID: e9a2b5d71c34
Revises: d8f1a3c64e2b
Create Date: 2026-06-11 00:00:00.000000

Adds the ``agent_run`` table: one row per agent run, reported at end-of-run over the mTLS
boundary, so an operator can see per host whether the *last scan actually succeeded* (and how
many entries / which scopes errored), not just that the agent last made contact. Append-only,
not partitioned, small (one row per scan), with a ``(host_id, created_at)`` index for the
"latest run per host" lookup. Chained off the current head ``d8f1a3c64e2b``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e9a2b5d71c34"
down_revision: str | None = "d8f1a3c64e2b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_run",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("host.id"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("entries_seen", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("rows_changed", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("pushed", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("scopes_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scopes_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finalized", sa.Integer(), nullable=True),
        sa.Column("error_summary", sa.String(length=1024), nullable=True),
        sa.Column("agent_version", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_agent_run_host_id", "agent_run", ["host_id"])
    op.create_index("ix_agent_run_created_at", "agent_run", ["created_at"])
    op.create_index("ix_agent_run_host_created", "agent_run", ["host_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_agent_run_host_created", table_name="agent_run")
    op.drop_index("ix_agent_run_created_at", table_name="agent_run")
    op.drop_index("ix_agent_run_host_id", table_name="agent_run")
    op.drop_table("agent_run")
