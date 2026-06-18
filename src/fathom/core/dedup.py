"""Content-based duplicate detection — report only (ADR-011, ADD 02 §Mode 2).

The engine groups candidate files by ``size → partial hash → full hash`` so a file is only
opened if it shares a size, and only fully hashed if its head+tail also collide. It
**never deletes** and never auto-selects what to remove: each confirmed group carries a
*non-binding, override-able* suggested keeper to speed an operator's manual choice
(ADR-011). Confirmed grouping requires a full BLAKE3 match — never size/partial alone — so
there is no false-positive grouping that could lead to a wrong deletion (ADD 09 §5).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Candidate:
    """A file considered for dedup. ``id`` is opaque (catalogue id, path, …).

    ``dev`` (st_dev) accompanies ``id`` so the agent full-bit funnel can update the right staged
    row — the staging identity is ``(host, volume, dev, inode)`` and two files in different ZFS
    child datasets can share an inode. It defaults to 0 (single-filesystem / server-side dedup,
    which keys on the catalogue surrogate id, not the staging key).
    """

    id: int | str
    path: str
    size: int
    dev: int = 0


@dataclass(frozen=True, slots=True)
class DuplicateGroup:
    """A confirmed set of byte-identical files."""

    full_hash: str
    size: int
    member_ids: tuple[int | str, ...]
    reclaimable_bytes: int
    suggested_keeper_id: int | str


class Hasher(Protocol):
    """Two-stage content hasher (see ``agent.reader.hasher.BackendHasher``)."""

    async def partial(self, path: str, size: int) -> str: ...

    async def full(self, path: str) -> str: ...


KeeperRule = Callable[[Sequence[Candidate]], Candidate]


def keep_shortest_path(members: Sequence[Candidate]) -> Candidate:
    """Default non-binding rule: suggest the shallowest, then lexically-first path."""
    return min(members, key=lambda c: (c.path.count("/"), c.path))


async def find_duplicates(
    candidates: Iterable[Candidate],
    hasher: Hasher,
    *,
    keeper: KeeperRule = keep_shortest_path,
    skip_empty: bool = True,
) -> list[DuplicateGroup]:
    """Return confirmed duplicate groups among ``candidates`` (report only).

    Args:
        candidates: Files to consider.
        hasher: Two-stage content hasher.
        keeper: Non-binding rule that suggests which member to keep.
        skip_empty: Skip zero-byte files (all trivially equal, nothing to reclaim).

    Returns:
        Confirmed groups, each with ``reclaimable_bytes = size * (members - 1)``.
    """
    by_size: dict[int, list[Candidate]] = defaultdict(list)
    for cand in candidates:
        if skip_empty and cand.size == 0:
            continue
        by_size[cand.size].append(cand)

    groups: list[DuplicateGroup] = []
    for size, sized in by_size.items():
        if len(sized) < 2:
            continue
        by_partial: dict[str, list[Candidate]] = defaultdict(list)
        for cand in sized:
            by_partial[await hasher.partial(cand.path, size)].append(cand)

        for partial_members in by_partial.values():
            if len(partial_members) < 2:
                continue
            by_full: dict[str, list[Candidate]] = defaultdict(list)
            for cand in partial_members:
                by_full[await hasher.full(cand.path)].append(cand)

            for full_hash, full_members in by_full.items():
                if len(full_members) < 2:
                    continue
                suggested = keeper(full_members)
                groups.append(
                    DuplicateGroup(
                        full_hash=full_hash,
                        size=size,
                        member_ids=tuple(m.id for m in full_members),
                        reclaimable_bytes=size * (len(full_members) - 1),
                        suggested_keeper_id=suggested.id,
                    )
                )
    return groups
