"""Tests for the dedup engine (report-only) and progressive hashing (ADR-011)."""

from __future__ import annotations

from pathlib import Path

from fathom.agent.reader.hasher import BackendHasher
from fathom.backends import PosixBackend
from fathom.core.dedup import Candidate, find_duplicates, keep_shortest_path


class FakeHasher:
    """Deterministic hasher keyed by path → (partial, full), to test the algorithm alone."""

    def __init__(self, table: dict[str, tuple[str, str]]) -> None:
        self._table = table
        self.partial_calls = 0
        self.full_calls = 0

    async def partial(self, path: str, size: int) -> str:
        self.partial_calls += 1
        return self._table[path][0]

    async def full(self, path: str) -> str:
        self.full_calls += 1
        return self._table[path][1]


async def test_confirmed_duplicates_grouped() -> None:
    cands = [
        Candidate(1, "/v/a", 100),
        Candidate(2, "/v/b/b", 100),
        Candidate(3, "/v/c", 100),
        Candidate(4, "/v/unique", 200),
    ]
    table = {
        "/v/a": ("P1", "F1"),
        "/v/b/b": ("P1", "F1"),  # identical to a
        "/v/c": ("P1", "F2"),  # partial collision but different full
        "/v/unique": ("P9", "F9"),
    }
    groups = await find_duplicates(cands, FakeHasher(table))
    assert len(groups) == 1
    g = groups[0]
    assert set(g.member_ids) == {1, 2}
    assert g.full_hash == "F1"
    assert g.reclaimable_bytes == 100  # one copy reclaimable
    assert g.suggested_keeper_id == 1  # shallower/lexically-first path


async def test_partial_short_circuits_full_hashing() -> None:
    # Two same-size files with different partials must never be fully hashed.
    cands = [Candidate(1, "/v/a", 50), Candidate(2, "/v/b", 50)]
    table = {"/v/a": ("PA", "FA"), "/v/b": ("PB", "FB")}
    hasher = FakeHasher(table)
    groups = await find_duplicates(cands, hasher)
    assert groups == []
    assert hasher.partial_calls == 2
    assert hasher.full_calls == 0  # short-circuited


async def test_empty_files_skipped() -> None:
    cands = [Candidate(1, "/v/x", 0), Candidate(2, "/v/y", 0)]
    assert await find_duplicates(cands, FakeHasher({})) == []


async def test_keeper_rule_override() -> None:
    cands = [Candidate(1, "/v/a", 10), Candidate(2, "/v/b", 10)]
    table = {"/v/a": ("P", "F"), "/v/b": ("P", "F")}
    groups = await find_duplicates(
        cands, FakeHasher(table), keeper=lambda members: max(members, key=lambda c: c.id)
    )
    assert groups[0].suggested_keeper_id == 2


def test_keep_shortest_path() -> None:
    chosen = keep_shortest_path(
        [Candidate(1, "/a/b/c", 1), Candidate(2, "/a/z", 1), Candidate(3, "/a/y", 1)]
    )
    assert chosen.id == 3  # shallowest, then lexical: "/a/y" < "/a/z"


async def test_end_to_end_real_files(tmp_path: Path) -> None:
    # Real bytes through PosixBackend + BLAKE3.
    (tmp_path / "one.bin").write_bytes(b"A" * 5000)
    (tmp_path / "copy.bin").write_bytes(b"A" * 5000)  # identical to one.bin
    (tmp_path / "other.bin").write_bytes(b"B" * 5000)  # same size, different content

    backend = PosixBackend()
    hasher = BackendHasher(backend)
    cands = [
        Candidate("one", str(tmp_path / "one.bin"), 5000),
        Candidate("copy", str(tmp_path / "copy.bin"), 5000),
        Candidate("other", str(tmp_path / "other.bin"), 5000),
    ]
    groups = await find_duplicates(cands, hasher)
    assert len(groups) == 1
    assert set(groups[0].member_ids) == {"one", "copy"}
    assert groups[0].reclaimable_bytes == 5000
