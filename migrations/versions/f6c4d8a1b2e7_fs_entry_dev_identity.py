"""fs_entry dev in entry identity (cross-dataset inode collision fix)

Revision ID: f6c4d8a1b2e7
Revises: e5b3c7f2a9d1
Create Date: 2026-06-06 19:10:00.000000

The filesystem-entry identity was ``(host_id, volume_id, inode)``. But the agent's
``cross_mounts`` mode scans one logical volume that spans multiple filesystems — ZFS child
datasets under a pool root (e.g. ``/scan/tank`` with 38 child datasets). Each dataset
has its OWN inode space and reuses low inode numbers, so files in DIFFERENT datasets share the
same inode and COLLIDE on the upsert key, clobbering each other (confirmed live: a cross-dataset
scan kept only the largest dataset's subtree). This migration threads the device id (``st_dev``)
into the identity so the key becomes ``(host_id, volume_id, dev, inode)``.

``dev`` defaults to ``0`` (server_default '0') so every existing row and every single-filesystem
scan is behaviour-preserving: within one filesystem ``inode`` is already unique, so ``dev = 0``
changes nothing.

Chained linearly off the current head ``e5b3c7f2a9d1`` (audit_prev_hash_unique) — one head, no
branch (``uv run alembic heads`` reported ``e5b3c7f2a9d1`` as the sole head before this revision).

Portability:

* **PostgreSQL** — ``fs_entry`` is the LIST-partitioned parent (partition keys ``host_id``,
  ``volume_id``). ``ADD COLUMN`` propagates to every current/future partition. The unique swap is
  raw ``ALTER`` DDL; the new unique still contains both partition-key columns, which PostgreSQL
  requires for any unique/PK on a partitioned table, so it is creatable and remains a valid
  ``ON CONFLICT`` target for the ingest upsert.
* **SQLite** (dev/test) — ``fs_entry`` is a plain table. SQLite cannot ``ALTER TABLE ... DROP/ADD
  CONSTRAINT``, so the column add + constraint swap run inside one Alembic batch block
  (``recreate='always'``) which table-copies the new shape in a single rebuild.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f6c4d8a1b2e7"
down_revision: str | None = "e5b3c7f2a9d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_UNIQUE = ("host_id", "volume_id", "inode")
_NEW_UNIQUE = ("host_id", "volume_id", "dev", "inode")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # Partitioned parent: ADD COLUMN propagates to all partitions; the unique swap is raw DDL
        # and the new unique keeps both partition-key columns (required on a partitioned table).
        op.execute("ALTER TABLE fs_entry ADD COLUMN dev bigint NOT NULL DEFAULT 0;")
        op.execute("ALTER TABLE fs_entry DROP CONSTRAINT uq_fs_entry_identity;")
        op.execute(
            "ALTER TABLE fs_entry ADD CONSTRAINT uq_fs_entry_identity "
            "UNIQUE (host_id, volume_id, dev, inode);"
        )
    else:
        # SQLite has no ALTER ADD/DROP CONSTRAINT: add the column and swap the unique in one
        # table-copy rebuild. The column carries server_default '0' so the rebuild backfills
        # every existing row to dev=0 (behaviour-preserving for single-filesystem scans).
        with op.batch_alter_table("fs_entry", recreate="always") as batch:
            batch.add_column(sa.Column("dev", sa.BigInteger(), nullable=False, server_default="0"))
            batch.drop_constraint("uq_fs_entry_identity", type_="unique")
            batch.create_unique_constraint("uq_fs_entry_identity", list(_NEW_UNIQUE))


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE fs_entry DROP CONSTRAINT uq_fs_entry_identity;")
        op.execute(
            "ALTER TABLE fs_entry ADD CONSTRAINT uq_fs_entry_identity "
            "UNIQUE (host_id, volume_id, inode);"
        )
        op.execute("ALTER TABLE fs_entry DROP COLUMN dev;")
    else:
        with op.batch_alter_table("fs_entry", recreate="always") as batch:
            batch.drop_constraint("uq_fs_entry_identity", type_="unique")
            batch.create_unique_constraint("uq_fs_entry_identity", list(_OLD_UNIQUE))
            batch.drop_column("dev")
