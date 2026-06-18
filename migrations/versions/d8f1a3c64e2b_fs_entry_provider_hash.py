"""fs_entry provider_hash + provider_hash_algo (ADR-028 phase 2: cross-cloud dedup signal)

Revision ID: d8f1a3c64e2b
Revises: c7e2f4a91b80
Create Date: 2026-06-11 00:00:00.000000

Adds two nullable columns to ``fs_entry`` for a **provider-attested** content hash and its
algorithm (rclone ``lsjson --hash`` — MD5/SHA-1/QuickXorHash the cloud provider already computed,
obtained with no file download). This is a distinct trust class from ``full_hash`` (BLAKE3, set
only by a real content read): it rides a metadata batch, lives in its own columns, and backs only
a report-only duplicate grouping — it never drives remediation. A partial index over
``(provider_hash_algo, provider_hash)`` (PostgreSQL: WHERE provider_hash IS NOT NULL) backs that
grouping scan and stays tiny because only provider-hashed rows populate it.

Both columns are nullable with no default, so every existing row and every normal scan is
behaviour-preserving (NULL = no provider hash). Chained off the current head ``c7e2f4a91b80``.

Portability:

* **PostgreSQL** — ``fs_entry`` is the LIST-partitioned parent; ``ADD COLUMN`` and a partial
  ``CREATE INDEX`` on the parent propagate to every current/future partition (PG 11+).
* **SQLite** (dev/test) — a plain table: add the columns and create a (non-partial) index in one
  batch rebuild.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d8f1a3c64e2b"
down_revision: str | None = "c7e2f4a91b80"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEX = "ix_fs_entry_provider_hash"


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE fs_entry ADD COLUMN provider_hash varchar(128);")
        op.execute("ALTER TABLE fs_entry ADD COLUMN provider_hash_algo varchar(32);")
        # Partial index: only provider-hashed rows are indexed, so it stays small on a huge table.
        op.execute(
            f"CREATE INDEX {_INDEX} ON fs_entry (provider_hash_algo, provider_hash) "
            "WHERE provider_hash IS NOT NULL;"
        )
    else:
        with op.batch_alter_table("fs_entry") as batch:
            batch.add_column(sa.Column("provider_hash", sa.String(length=128), nullable=True))
            batch.add_column(sa.Column("provider_hash_algo", sa.String(length=32), nullable=True))
        op.create_index(_INDEX, "fs_entry", ["provider_hash_algo", "provider_hash"])


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"DROP INDEX IF EXISTS {_INDEX};")
        op.execute("ALTER TABLE fs_entry DROP COLUMN provider_hash_algo;")
        op.execute("ALTER TABLE fs_entry DROP COLUMN provider_hash;")
    else:
        op.drop_index(_INDEX, table_name="fs_entry")
        with op.batch_alter_table("fs_entry") as batch:
            batch.drop_column("provider_hash_algo")
            batch.drop_column("provider_hash")
