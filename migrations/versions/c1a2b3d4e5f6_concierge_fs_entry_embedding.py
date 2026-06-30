"""concierge fs_entry_embedding (pgvector) — ADR-035 Phase 2 semantic search

Revision ID: c1a2b3d4e5f6
Revises: b4d7e9f2a1c5
Create Date: 2026-06-18 00:00:00.000000

Adds the optional ``fs_entry_embedding`` table that backs the concierge's semantic ("find by
meaning") search. PostgreSQL-only DDL: it enables the ``vector`` extension and creates the table
with a real ``vector(768)`` column + an HNSW cosine index. On SQLite (dev/test) the table is created
by ``Base.metadata.create_all`` from the ORM model's portable JSON variant, so this migration is a
no-op there. The table is keyed to the partitioned ``fs_entry`` by business key with no DB FK
(app-enforced, like ``dup_member``). Behaviour-preserving: nothing reads it unless the concierge
embedding pipeline is enabled. Chained off ``b4d7e9f2a1c5``.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c1a2b3d4e5f6"
down_revision: str | None = "b4d7e9f2a1c5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

log = logging.getLogger("alembic.runtime.migration")

# Must match fathom.core.catalogue.embedding_meta.EMBED_DIM and Settings.concierge_embedding_dim.
_EMBED_DIM = 768


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite/dev: the ORM model's JSON variant is created by create_all; no vector DDL here.
        return
    # pgvector-optional: the production image may be a plain ``postgres`` without the ``vector``
    # extension available. The concierge semantic index is default-OFF
    # (concierge_embeddings_enabled), so if pgvector cannot be installed we skip the table entirely
    # — the embedding worker and the semantic query degrade gracefully to substring search. Probe
    # availability first so a failed CREATE EXTENSION can never poison the migration transaction
    # (asyncpg aborts the whole tx).
    available = bind.execute(
        sa.text("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'")
    ).scalar()
    if not available:
        log.warning(
            "pgvector ('vector') extension is not available on this PostgreSQL server; skipping "
            "fs_entry_embedding. Concierge semantic search will fall back to substring find. "
            "Install pgvector (e.g. the pgvector/pgvector image) and re-run to enable it."
        )
        return
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute(
        f"""
        CREATE TABLE fs_entry_embedding (
            id BIGSERIAL PRIMARY KEY,
            entry_id BIGINT NOT NULL,
            host_id INTEGER NOT NULL,
            volume_id INTEGER NOT NULL,
            text_hash VARCHAR(64) NOT NULL,
            embedding vector({_EMBED_DIM}) NOT NULL,
            embedded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_embedding_entry UNIQUE (entry_id, host_id, volume_id)
        )
        """
    )
    op.create_index("ix_fs_entry_embedding_entry_id", "fs_entry_embedding", ["entry_id"])
    op.create_index("ix_fs_entry_embedding_host_id", "fs_entry_embedding", ["host_id"])
    op.create_index("ix_fs_entry_embedding_volume_id", "fs_entry_embedding", ["volume_id"])
    # HNSW index for cosine-distance (``<=>``) nearest-neighbour search.
    op.execute(
        "CREATE INDEX ix_fs_entry_embedding_vec ON fs_entry_embedding "
        "USING hnsw (embedding vector_cosine_ops)"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    # IF EXISTS: the table may never have been created (pgvector unavailable at upgrade time).
    op.execute("DROP TABLE IF EXISTS fs_entry_embedding")
    # The ``vector`` extension is left in place — other features may rely on it; dropping an
    # extension is a destructive, deployment-wide action, not this migration's concern.
