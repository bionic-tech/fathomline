"""Concierge embedding pipeline (ADR-035 Phase 2 + addendum) — path-name vectors for search.

Builds + maintains the ``fs_entry_embedding`` table from **file names + paths only — never file
content** (metadata stays on the catalogue boundary). It is incremental and bounded: each batch
embeds at most ``batch`` present, **data-volume** files that have no embedding yet, so the one-time
backfill is cap-able and steady-state cost tracks new files, not catalogue size. Embeddings come
from a pluggable :class:`~fathom.inference.embeddings.EmbeddingProvider` (local Ollama by default;
Voyage/OpenAI behind the egress gate). **Freshness:** :func:`prune_orphan_embeddings` drops vectors
whose entry is no longer present (delete/rename), so the index never drifts — a rename makes a fresh
entry (embedded next tick) and retires the old one. All gated by ``concierge_embeddings_enabled``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import cast

from sqlalchemy import CursorResult, delete, exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.embedding_meta import FsEntryEmbedding
from fathom.core.catalogue.models import FsEntryRow, Volume
from fathom.inference.embeddings import INPUT_DOCUMENT, EmbeddingProvider
from fathom.logging import get_logger

_log = get_logger("fathom.core.concierge.embeddings")


@dataclass(slots=True)
class EmbedCandidate:
    """A file that needs an embedding (present, on a data volume, not yet embedded)."""

    entry_id: int
    host_id: int
    volume_id: int
    name: str
    path: str


def embed_text(name: str, path: str) -> str:
    """The text embedded for a file: its name plus its path (no content is ever read)."""
    return f"{name}\n{path}"


def text_hash(text: str) -> str:
    """A short stable digest of the embedded text (lets the pipeline detect unchanged entries)."""
    return hashlib.blake2b(text.encode("utf-8", "ignore"), digest_size=16).hexdigest()


async def rows_needing_embedding(
    session: AsyncSession, *, limit: int, scope: ScopeFilter | None = None
) -> list[EmbedCandidate]:
    """Select present, data-volume files that have no embedding yet (incremental backfill unit).

    Files only (not directories), ``present=True``, ``Volume.kind == 'data'`` (OS/system volumes are
    never embedded), LEFT JOIN ``fs_entry_embedding`` filtered to rows with no embedding. Bounded by
    ``limit`` so the backfill is cap-able per tick. ``scope`` (optional) narrows an admin-triggered
    run; the background worker runs unscoped (global).
    """
    stmt = (
        select(
            FsEntryRow.id,
            FsEntryRow.host_id,
            FsEntryRow.volume_id,
            FsEntryRow.name,
            FsEntryRow.path,
        )
        .join(Volume, Volume.id == FsEntryRow.volume_id)
        .outerjoin(
            FsEntryEmbedding,
            (FsEntryEmbedding.entry_id == FsEntryRow.id)
            & (FsEntryEmbedding.host_id == FsEntryRow.host_id)
            & (FsEntryEmbedding.volume_id == FsEntryRow.volume_id),
        )
        .where(
            FsEntryRow.present.is_(True),
            FsEntryRow.is_dir.is_(False),
            Volume.kind == "data",
            FsEntryEmbedding.id.is_(None),
        )
        .limit(limit)
    )
    if scope is not None:
        stmt = scope.apply(
            stmt, host_col=FsEntryRow.host_id, volume_col=FsEntryRow.volume_id, kind_col=Volume.kind
        )
    rows = (await session.execute(stmt)).all()
    return [
        EmbedCandidate(
            entry_id=r.id, host_id=r.host_id, volume_id=r.volume_id, name=r.name, path=r.path
        )
        for r in rows
    ]


async def prune_orphan_embeddings(session: AsyncSession) -> int:
    """Delete embeddings whose entry is no longer present (delete/rename); return rows removed.

    Keeps the semantic index fresh (ADR-035 addendum): a deleted or renamed file's vector is dropped
    so it can't surface in results and the index doesn't drift. A rename makes a fresh entry
    (embedded next batch), while this retires the old (``present=False``) one. Pure delete; no
    embedding I/O. Runs on the worker tick before the embed pass.
    """
    stmt = delete(FsEntryEmbedding).where(
        ~exists(
            select(FsEntryRow.id).where(
                FsEntryRow.id == FsEntryEmbedding.entry_id,
                FsEntryRow.host_id == FsEntryEmbedding.host_id,
                FsEntryRow.volume_id == FsEntryEmbedding.volume_id,
                FsEntryRow.present.is_(True),
            )
        )
    )
    result = cast(CursorResult[object], await session.execute(stmt))
    removed = int(result.rowcount or 0)
    if removed:
        _log.info("pruned orphan embeddings", extra={"removed": removed})
    return removed


async def run_embedding_batch(
    session: AsyncSession,
    *,
    provider: EmbeddingProvider,
    batch: int,
    scope: ScopeFilter | None = None,
) -> int:
    """Embed one batch of not-yet-embedded files and persist the vectors; return the count embedded.

    The unit of work for the worker and any admin/inline invocation. Returns 0 when nothing needs
    embedding (backfill complete / steady state). Catalogue rows are embedded as ``document`` (the
    query is embedded as ``query`` at search time — the input_type asymmetry). Read-only against
    ``fs_entry``; only inserts into ``fs_entry_embedding``.
    """
    candidates = await rows_needing_embedding(session, limit=batch, scope=scope)
    if not candidates:
        return 0
    texts = [embed_text(c.name, c.path) for c in candidates]
    vectors = await provider.embed(texts, input_type=INPUT_DOCUMENT)
    for cand, text, vector in zip(candidates, texts, vectors, strict=True):
        session.add(
            FsEntryEmbedding(
                entry_id=cand.entry_id,
                host_id=cand.host_id,
                volume_id=cand.volume_id,
                text_hash=text_hash(text),
                embedding=vector,
            )
        )
    await session.flush()
    _log.info("concierge embedded batch", extra={"count": len(candidates)})
    return len(candidates)
