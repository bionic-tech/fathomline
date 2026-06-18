"""dup_member.is_mount_alias — flag cross-mount alias duplicates (NFS/SMB false positives)

Revision ID: a2e8f4c1d9b6
Revises: f1b6c2a9d34e
Create Date: 2026-06-14 00:00:00.000000

Adds a non-null ``dup_member.is_mount_alias`` (default False). A member that lives on a
network-mounted volume (NFS/SMB/sshfs) is a remote *view* of bytes physically stored on another
host — the same physical file seen twice, not a reclaimable copy. The dedup builder flags these so
the UI highlights them as cross-mount false positives and excludes them from the group's
``reclaimable_bytes`` (cross-mount dedup, ADR-032). Behaviour-preserving for existing rows (dup
groups are rebuilt on every full-bit finalize, so the flag is repopulated on the next run).
Chained off ``f1b6c2a9d34e``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a2e8f4c1d9b6"
down_revision: str | None = "f1b6c2a9d34e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("dup_member") as batch:
        batch.add_column(
            sa.Column(
                "is_mount_alias",
                sa.Boolean(),
                nullable=False,
                server_default="0",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("dup_member") as batch:
        batch.drop_column("is_mount_alias")
