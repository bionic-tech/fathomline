"""Concierge embedding-pipeline tests (ADR-035 Phase 2 + addendum).

The vector similarity query itself is PostgreSQL/pgvector-only, so these cover what runs on SQLite:
the incremental selection of files needing embedding (present, data-volume, not-yet-embedded;
dirs/system/deleted excluded), the batch runner persisting vectors via a fake EmbeddingProvider
(documents embedded as ``document``), prune-on-delete dropping orphaned vectors, and the service
degrading semantic search to substring find when the vector operator isn't available.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.core.catalogue.embedding_meta import FsEntryEmbedding
from fathom.core.catalogue.models import Base, FsEntryRow, Host, Volume
from fathom.core.concierge import embeddings
from fathom.core.concierge.service import (
    ConciergeIntent,
    ConciergeService,
    ConciergeTool,
)
from fathom.inference.embeddings import INPUT_DOCUMENT, INPUT_QUERY


class FakeEmbedder:
    """Records (texts, input_type) and returns short JSON-friendly vectors (no network)."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], str]] = []

    async def embed(self, texts: list[str], *, input_type: str) -> list[list[float]]:
        self.calls.append((tuple(texts), input_type))
        return [[0.1, 0.2, 0.3] for _ in texts]


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _seed(session: AsyncSession) -> tuple[Volume, Volume]:
    host = Host(name="nas-1", cert_fingerprint="fp")
    session.add(host)
    await session.flush()
    data = Volume(host_id=host.id, mountpoint="/mnt/data", fs_type="zfs", device="d", transport="s")
    system = Volume(
        host_id=host.id, mountpoint="/", fs_type="ext4", device="r", transport="s", kind="system"
    )
    session.add_all([data, system])
    await session.flush()
    rows = [
        FsEntryRow(
            host_id=host.id, volume_id=data.id, name="a.txt", path="/mnt/data/a.txt", inode=1
        ),
        FsEntryRow(
            host_id=host.id, volume_id=data.id, name="b.txt", path="/mnt/data/b.txt", inode=2
        ),
        FsEntryRow(
            host_id=host.id,
            volume_id=data.id,
            name="dir",
            path="/mnt/data/dir",
            inode=3,
            is_dir=True,
        ),
        FsEntryRow(
            host_id=host.id,
            volume_id=data.id,
            name="gone.txt",
            path="/mnt/data/gone.txt",
            inode=4,
            present=False,
        ),
        FsEntryRow(host_id=host.id, volume_id=system.id, name="os.bin", path="/os.bin", inode=5),
    ]
    session.add_all(rows)
    await session.flush()
    return data, system


async def test_rows_needing_embedding_filters(session: AsyncSession) -> None:
    await _seed(session)
    candidates = await embeddings.rows_needing_embedding(session, limit=100)
    names = sorted(c.name for c in candidates)
    # Only present, non-dir, data-volume files with no embedding yet.
    assert names == ["a.txt", "b.txt"]


async def test_run_embedding_batch_persists_and_is_incremental(session: AsyncSession) -> None:
    await _seed(session)
    provider = FakeEmbedder()
    n = await embeddings.run_embedding_batch(session, provider=provider, batch=100)
    assert n == 2
    # Catalogue rows are embedded as documents (the input_type asymmetry).
    assert provider.calls[0][1] == INPUT_DOCUMENT
    stored = (await session.execute(select(FsEntryEmbedding))).scalars().all()
    assert len(stored) == 2
    assert all(row.embedding == [0.1, 0.2, 0.3] for row in stored)
    # Second run: everything is embedded → nothing to do.
    assert await embeddings.run_embedding_batch(session, provider=provider, batch=100) == 0


async def test_prune_orphan_embeddings_drops_absent_entries(session: AsyncSession) -> None:
    await _seed(session)
    # Embed the present files, then add a stray vector for the deleted gone.txt (inode 4).
    provider = FakeEmbedder()
    await embeddings.run_embedding_batch(session, provider=provider, batch=100)
    gone = (
        await session.execute(select(FsEntryRow).where(FsEntryRow.inode == 4))
    ).scalar_one()
    session.add(
        FsEntryEmbedding(
            entry_id=gone.id,
            host_id=gone.host_id,
            volume_id=gone.volume_id,
            text_hash="x",
            embedding=[0.0, 0.0, 0.0],
        )
    )
    await session.flush()
    removed = await embeddings.prune_orphan_embeddings(session)
    assert removed == 1  # only the present=False entry's vector is dropped
    remaining = (await session.execute(select(FsEntryEmbedding))).scalars().all()
    assert len(remaining) == 2
    assert gone.id not in {r.entry_id for r in remaining}


async def test_semantic_degrades_to_find_when_vector_unavailable(session: AsyncSession) -> None:
    # Embeddings "enabled", but the pgvector operator can't run on SQLite → the service must catch
    # that and fall back to the substring find, still returning the matching file.
    await _seed(session)

    class _FakeProvider:
        async def complete(self, *, system: str, user: str, schema: object) -> object:
            if schema is ConciergeIntent:
                return ConciergeIntent(tool=ConciergeTool.SEMANTIC_SEARCH, name_or_fragment="a.txt")
            from fathom.core.concierge.service import ConciergeAnswer

            return ConciergeAnswer(answer="ok")

    embedder = FakeEmbedder()
    svc = ConciergeService(
        session,
        _FakeProvider(),  # type: ignore[arg-type]
        model="fake",
        embeddings_enabled=True,
        embedding_provider=embedder,
    )
    result = await svc.ask("find the file about a")
    assert result.considered == 1
    assert result.citations[0].path == "/mnt/data/a.txt"  # found via substring fallback
    # The query was embedded as a query (the asymmetry), proving the provider seam is wired.
    assert embedder.calls and embedder.calls[0][1] == INPUT_QUERY
