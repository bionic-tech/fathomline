"""fullbit dedup schema

Revision ID: 52044159af8a
Revises: b7e2c1a4d9f0
Create Date: 2026-06-05 21:30:00.000000

Full-bit + dedup schema (fullbit-dedup spec; ADD 09 §2). Chained linearly off the current
head ``b7e2c1a4d9f0`` (auth_rbac) — one head, no branch.

Two changes:

1. ``fs_entry`` gains ``partial_hash`` / ``full_hash`` / ``hashed_at`` (NULL = never
   full-bit-hashed; set only by a full-bit ingest). On PostgreSQL ``fs_entry`` is the
   LIST-partitioned parent, so ``ALTER TABLE ... ADD COLUMN`` and ``CREATE INDEX ... ON
   fs_entry`` propagate to every current and future partition — no per-partition DDL needed
   (risks: partitioned-parent ALTER). The grouping index is created **partial**
   (``WHERE full_hash IS NOT NULL``) on PostgreSQL so it covers only full-bit-hashed rows and
   stays tiny at 30-40M rows (risks: estate-wide grouping scan). SQLite (dev/test) gets a
   plain composite index for parity.

2. ``dup_group`` / ``dup_member`` are created as plain, portable tables (DEFAULTS owner
   ruling). ``dup_member`` references ``fs_entry`` by a non-FK ``entry_id`` plus the
   ``(host_id, volume_id)`` business key — a composite FK into the partitioned parent (PK
   ``(id, host_id, volume_id)``) is intentionally avoided (design_questions).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "52044159af8a"
down_revision: str | None = "b7e2c1a4d9f0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _add_fs_entry_hash_columns() -> None:
    """Add the three hash columns + the (volume_id, full_hash) grouping index.

    On PostgreSQL the column adds and the index create target the partitioned parent and
    propagate to all partitions; the index is partial so only full-bit-hashed rows are
    indexed. On SQLite a plain table + plain composite index keep schema parity.
    """
    op.add_column("fs_entry", sa.Column("partial_hash", sa.String(length=64), nullable=True))
    op.add_column("fs_entry", sa.Column("full_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "fs_entry",
        sa.Column("hashed_at", sa.DateTime(timezone=True), nullable=True),
    )
    if op.get_bind().dialect.name == "postgresql":
        # Partitioned-parent index propagates to partitions; partial so it covers only the
        # rows a full-bit scan actually hashed (keeps it small at estate scale).
        op.execute(
            "CREATE INDEX ix_fs_entry_volume_full_hash "
            "ON fs_entry (volume_id, full_hash) WHERE full_hash IS NOT NULL;"
        )
    else:
        op.create_index(
            "ix_fs_entry_volume_full_hash",
            "fs_entry",
            ["volume_id", "full_hash"],
            unique=False,
        )


def _create_dup_tables() -> None:
    """Create the portable ``dup_group`` / ``dup_member`` report tables (ADD 09 §2)."""
    op.create_table(
        "dup_group",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("full_hash", sa.String(length=64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False),
        sa.Column("reclaimable_bytes", sa.BigInteger(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=True),
        sa.Column("job_id", sa.String(length=64), nullable=True),
        sa.Column("suggested_keeper_entry_id", sa.BigInteger(), nullable=True),
        sa.Column("suggested_keeper_reason", sa.String(length=255), nullable=True),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dup_group_full_hash"), "dup_group", ["full_hash"], unique=False)

    op.create_table(
        "dup_member",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        # entry_id is a non-FK reference into the partitioned fs_entry (design_questions).
        sa.Column("entry_id", sa.BigInteger(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("volume_id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(length=4096), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["dup_group.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dup_member_group_id"), "dup_member", ["group_id"], unique=False)


def upgrade() -> None:
    _add_fs_entry_hash_columns()
    _create_dup_tables()


def downgrade() -> None:
    op.drop_index(op.f("ix_dup_member_group_id"), table_name="dup_member")
    op.drop_table("dup_member")
    op.drop_index(op.f("ix_dup_group_full_hash"), table_name="dup_group")
    op.drop_table("dup_group")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS ix_fs_entry_volume_full_hash;")
    else:
        op.drop_index("ix_fs_entry_volume_full_hash", table_name="fs_entry")
    op.drop_column("fs_entry", "hashed_at")
    op.drop_column("fs_entry", "full_hash")
    op.drop_column("fs_entry", "partial_hash")
