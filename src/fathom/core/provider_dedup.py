"""Provider-hash duplicate grouping (ADR-028 phase 2) — read-only, never drives remediation.

Groups catalogue entries that carry a **provider-attested** content hash (set by the rclone
backend from ``lsjson --hash`` — the cloud provider's own MD5/SHA-1/QuickXorHash, obtained with no
download) by ``(algo, hash, size)``. This surfaces "these objects look identical per the provider"
across one or more cloud remotes at **zero egress** — the headline of ADR-028.

It is deliberately separate from :mod:`fathom.core.dedup_service` (the content-verified BLAKE3
``DupGroup`` builder): provider hashes are a weaker, provider-trusted signal, so they are
report-only and **never** feed the remediation/keeper path (which keys on the BLAKE3
``full_hash``). Only like-with-like compares — two entries group only if their *algorithm* matches,
so an MD5 from Drive is never compared to a SHA-1 from Dropbox.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.models import FsEntryRow


@dataclass(frozen=True, slots=True)
class ProviderDupMember:
    """One member of a provider-hash duplicate group."""

    entry_id: int
    host_id: int
    volume_id: int
    path: str


@dataclass(frozen=True, slots=True)
class ProviderDupGroup:
    """A set of entries sharing one ``(algo, hash, size)`` per the provider (report-only)."""

    algo: str
    provider_hash: str
    size: int
    members: tuple[ProviderDupMember, ...]

    @property
    def reclaimable_bytes(self) -> int:
        """Bytes freed if all but one copy were removed (informational — not a remediation plan)."""
        return self.size * (len(self.members) - 1)


def _make_group(
    key: tuple[str, str, int] | None,
    members: list[ProviderDupMember],
    min_members: int,
) -> ProviderDupGroup | None:
    """Build a group from a completed run, or ``None`` if it is below the duplicate threshold."""
    if key is None or len(members) < min_members:
        return None
    algo, phash, size = key
    return ProviderDupGroup(algo=algo, provider_hash=phash, size=size, members=tuple(members))


async def iter_provider_hash_duplicates(
    session: AsyncSession,
    *,
    scope: ScopeFilter | None = None,
    volume_ids: Sequence[int] | None = None,
    min_members: int = 2,
) -> AsyncIterator[ProviderDupGroup]:
    """Yield provider-hash duplicate groups one at a time — truly bounded memory, zero egress.

    Streams a single index-ordered scan over only the provider-hashed, present rows and yields
    each completed ``(algo, hash, size)`` run as it ends, so memory is one group at a time
    regardless of estate size. This is the variant to use behind an API at scale.

    ``scope`` (when not global) pushes the server-authoritative RBAC predicate into the scan via
    :meth:`ScopeFilter.apply` — an empty non-global scope matches nothing (fail-closed), so a
    group can never include an out-of-scope member. ``volume_ids`` additionally narrows the scan
    (e.g. the route's ``volume_id`` query param); ``[]`` yields nothing.
    """
    if volume_ids is not None and not volume_ids:
        return
    stmt = (
        select(
            FsEntryRow.provider_hash_algo,
            FsEntryRow.provider_hash,
            FsEntryRow.size_logical,
            FsEntryRow.id,
            FsEntryRow.host_id,
            FsEntryRow.volume_id,
            FsEntryRow.path,
        )
        .where(
            FsEntryRow.provider_hash.is_not(None),
            FsEntryRow.provider_hash_algo.is_not(None),
            FsEntryRow.present.is_(True),
            FsEntryRow.is_dir.is_(False),
        )
        # Pairing size with (algo, hash) makes a cross-size hash collision impossible to mis-group,
        # mirroring the BLAKE3 path. Ordered so consecutive rows form a group.
        .order_by(
            FsEntryRow.provider_hash_algo,
            FsEntryRow.provider_hash,
            FsEntryRow.size_logical,
        )
    )
    if volume_ids is not None:
        stmt = stmt.where(FsEntryRow.volume_id.in_(volume_ids))
    if scope is not None:
        # Server-authoritative RBAC: never group an out-of-scope member (fail-closed on empty).
        stmt = scope.apply(stmt, host_col=FsEntryRow.host_id, volume_col=FsEntryRow.volume_id)

    cur_key: tuple[str, str, int] | None = None
    cur: list[ProviderDupMember] = []
    result = await session.stream(stmt)
    async for algo, phash, size, entry_id, host_id, volume_id, path in result:
        key = (algo, phash, size)
        if key != cur_key:
            group = _make_group(cur_key, cur, min_members)
            if group is not None:
                yield group
            cur_key = key
            cur = []
        cur.append(
            ProviderDupMember(entry_id=entry_id, host_id=host_id, volume_id=volume_id, path=path)
        )
    last = _make_group(cur_key, cur, min_members)
    if last is not None:
        yield last


async def find_provider_hash_duplicates(
    session: AsyncSession,
    *,
    scope: ScopeFilter | None = None,
    volume_ids: Sequence[int] | None = None,
    min_members: int = 2,
    limit: int | None = None,
) -> list[ProviderDupGroup]:
    """Collect provider-hash duplicate groups into a list (convenience wrapper).

    The DB cursor is streamed, but this **materializes** the groups into the returned list. For an
    unbounded estate-scale scan prefer :func:`iter_provider_hash_duplicates` (yields one group at a
    time); behind an API, pass ``limit`` (and ``scope``) so the result list is bounded. Returns at
    most ``limit`` groups when given; stops scanning once reached.
    """
    out: list[ProviderDupGroup] = []
    async for group in iter_provider_hash_duplicates(
        session, scope=scope, volume_ids=volume_ids, min_members=min_members
    ):
        out.append(group)
        if limit is not None and len(out) >= limit:
            break
    return out
