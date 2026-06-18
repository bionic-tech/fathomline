"""incremental change feed

Revision ID: 9e41f1184d8a
Revises: 52044159af8a
Create Date: 2026-06-06 09:10:00.000000

Incremental subsystem schema (incremental spec; ADR-006, ADD 09 §2). Chained linearly off
the current head ``52044159af8a`` (fullbit_dedup) — one head, no branch.

Three changes:

1. ``fs_entry`` gains ``present`` (default TRUE) + ``removed_at`` — the *explicit* deletion
   markers the incremental owner ruling mandates ("an explicit present/removed_at marker, NOT
   snapshot-staleness inference"). On PostgreSQL ``fs_entry`` is the LIST-partitioned parent,
   so ``ALTER TABLE ... ADD COLUMN`` propagates to every current and future partition — no
   per-partition DDL (risks: partitioned-parent ALTER). The partial ``WHERE present = false``
   index keeps the "what's been deleted" scan tiny (the overwhelming majority of rows are
   present), mirroring the fullbit partial-index pattern.

2. ``volume`` gains ``change_log_enabled`` (default TRUE) — the per-volume churn toggle
   (incremental owner ruling: change_log default ON per volume). ``volume`` is a plain table on
   both backends, so a portable ``add_column`` suffices.

3. ``change_log`` is created as a plain, portable table (the churn "what changed" feed, ADD 09
   §2/§4), retention-capped at 90 days by the pruner — the DDL just provides the
   ``(volume_id, ts)`` index that backs both the churn read and the retention scan.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9e41f1184d8a"
down_revision: str | None = "52044159af8a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _add_presence_markers() -> None:
    """Add ``present`` / ``removed_at`` to ``fs_entry`` + the partial 'removed' index.

    On PostgreSQL the column adds and the index create target the partitioned parent and
    propagate to all partitions; the index is partial (``WHERE present = false``) so it covers
    only the small set of soft-deleted rows. On SQLite a plain table + plain index keep schema
    parity. ``server_default`` backfills existing rows to ``present = TRUE`` so the migration is
    safe to run against a populated catalogue (every pre-existing entry is, by definition,
    present until a feed says otherwise).
    """
    op.add_column(
        "fs_entry",
        sa.Column(
            "present",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )
    op.add_column(
        "fs_entry",
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )
    if op.get_bind().dialect.name == "postgresql":
        # Partial index: only the (rare) soft-deleted rows are indexed, keeping it tiny at
        # estate scale while still backing the "what's been removed" churn/audit scan.
        op.execute(
            "CREATE INDEX ix_fs_entry_removed "
            "ON fs_entry (volume_id, removed_at) WHERE present = false;"
        )
    else:
        op.create_index(
            "ix_fs_entry_removed",
            "fs_entry",
            ["volume_id", "removed_at"],
            unique=False,
        )


def _add_change_log_toggle() -> None:
    """Add the per-volume ``change_log_enabled`` toggle (default ON)."""
    op.add_column(
        "volume",
        sa.Column(
            "change_log_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def _create_change_log() -> None:
    """Create the portable ``change_log`` churn table + its ``(volume_id, ts)`` index."""
    op.create_table(
        "change_log",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("volume_id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(length=4096), nullable=False),
        sa.Column("change_type", sa.String(length=8), nullable=False),
        sa.Column("size_delta", sa.BigInteger(), nullable=False),
        sa.Column(
            "ts", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(["volume_id"], ["volume.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_change_log_volume_id"), "change_log", ["volume_id"], unique=False)
    op.create_index(op.f("ix_change_log_ts"), "change_log", ["ts"], unique=False)
    op.create_index("ix_change_log_volume_ts", "change_log", ["volume_id", "ts"], unique=False)


def upgrade() -> None:
    _add_presence_markers()
    _add_change_log_toggle()
    _create_change_log()


def downgrade() -> None:
    op.drop_index("ix_change_log_volume_ts", table_name="change_log")
    op.drop_index(op.f("ix_change_log_ts"), table_name="change_log")
    op.drop_index(op.f("ix_change_log_volume_id"), table_name="change_log")
    op.drop_table("change_log")
    op.drop_column("volume", "change_log_enabled")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS ix_fs_entry_removed;")
    else:
        op.drop_index("ix_fs_entry_removed", table_name="fs_entry")
    op.drop_column("fs_entry", "removed_at")
    op.drop_column("fs_entry", "present")
