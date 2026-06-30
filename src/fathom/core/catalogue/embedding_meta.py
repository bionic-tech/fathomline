"""``fs_entry_embedding`` ORM table (ADR-035 Phase 2) — pgvector path-name embeddings.

Backs the concierge's optional semantic ("find by meaning") search. It stores a vector embedding of
each data-volume file's **name + path tail only — never file content** (metadata-only, stays on the
catalogue trust boundary). The column is portable: a real ``vector(N)`` on PostgreSQL (pgvector), a
JSON array on SQLite so the test suite stays green — the actual similarity operator (``<=>``) is
PostgreSQL-only and used solely by the semantic-search query.

Like :class:`~fathom.core.catalogue.models.DupMember`, it references the LIST-partitioned
``fs_entry`` by the ``(entry_id, host_id, volume_id)`` business key with **no** composite DB FK
(not creatable against the partitioned parent); integrity is app-enforced. ``host_id``/``volume_id``
let the semantic query apply the same server-authoritative scope predicate as every other read.
"""

from __future__ import annotations

from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, BigInteger, DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from fathom.core.catalogue.models import Base

# The embedding dimension. MUST match ``Settings.concierge_embedding_dim`` and the embedding model
# (Ollama ``nomic-embed-text`` = 768). Changing it requires a new migration + a re-embed.
EMBED_DIM = 768


class FsEntryEmbedding(Base):
    """One file's path-name embedding for semantic search (PostgreSQL vector / SQLite JSON)."""

    __tablename__ = "fs_entry_embedding"
    __table_args__ = (
        UniqueConstraint("entry_id", "host_id", "volume_id", name="uq_embedding_entry"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    entry_id: Mapped[int] = mapped_column(BigInteger, index=True)
    host_id: Mapped[int] = mapped_column(Integer, index=True)
    volume_id: Mapped[int] = mapped_column(Integer, index=True)
    # BLAKE2b hex of the embedded text (name + path tail); lets the pipeline skip re-embedding an
    # unchanged entry and detect a changed one.
    text_hash: Mapped[str] = mapped_column(String(64))
    # vector(EMBED_DIM) on PostgreSQL (pgvector), a JSON array on SQLite. ``Vector`` is the BASE
    # type (not the variant) so its ``cosine_distance`` comparator is available for the semantic
    # query; ``with_variant`` only swaps DDL/storage to JSON on SQLite, where the operator is N/A.
    embedding: Mapped[list[float]] = mapped_column(
        Vector(EMBED_DIM).with_variant(JSON(), "sqlite")
    )
    embedded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
