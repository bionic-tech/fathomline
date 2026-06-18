"""volume.display_name — human label for synthetic-mountpoint (remote) volumes (ADR-029)

Revision ID: f1b6c2a9d34e
Revises: e9a2b5d71c34
Create Date: 2026-06-11 00:00:00.000000

Adds a nullable ``volume.display_name``. Remote/cloud volumes store a POSIX-absolute synthetic
``mountpoint`` (e.g. ``/rclone/gdrive/Backups``) so they satisfy the catalogue/ingest/read path
contract; ``display_name`` carries the pretty ``rclone://gdrive/Backups`` form the UI shows.
NULL for local volumes (the mountpoint is already the natural display). Behaviour-preserving for
existing rows. Chained off ``e9a2b5d71c34``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f1b6c2a9d34e"
down_revision: str | None = "e9a2b5d71c34"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("volume") as batch:
        batch.add_column(sa.Column("display_name", sa.String(length=4096), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("volume") as batch:
        batch.drop_column("display_name")
