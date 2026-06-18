"""dup_group.scope -> JSONB on PostgreSQL (fix estate-wide dedup rebuild)

Revision ID: c7e2f4a91b80
Revises: b3d1e8f4a960
Create Date: 2026-06-09 19:40:00.000000

The estate-wide dedup rebuild looks a group up BY its scope
(``SELECT ... WHERE dup_group.scope = :scope``) before replacing it. The ``json`` column type has
**no equality operator on PostgreSQL** (``operator does not exist: json = json``), so that query
threw in production and the post-full-bit dedup rebuild failed — the ``/duplicates`` view stayed
empty even though content was hashed and cross-host hash collisions existed. It passed in the
SQLite test suite only because SQLite compares the JSON text directly.

Convert the column to ``jsonb`` (which supports ``=``) on PostgreSQL. SQLite keeps the portable
``JSON``/text form (the model uses ``JSON().with_variant(JSONB, 'postgresql')``), so this migration
is a no-op there. Existing values cast cleanly (``USING scope::jsonb``); the column is nullable so
NULLs are unaffected.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c7e2f4a91b80"
down_revision: str | None = "b3d1e8f4a960"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # PostgreSQL-only: SQLite has a single dynamic-typed JSON/text affinity, no jsonb to convert to.
    if op.get_bind().dialect.name != "postgresql":
        return
    op.alter_column(
        "dup_group",
        "scope",
        type_=postgresql.JSONB(),
        existing_type=postgresql.JSON(),
        existing_nullable=True,
        postgresql_using="scope::jsonb",
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.alter_column(
        "dup_group",
        "scope",
        type_=postgresql.JSON(),
        existing_type=postgresql.JSONB(),
        existing_nullable=True,
        postgresql_using="scope::json",
    )
