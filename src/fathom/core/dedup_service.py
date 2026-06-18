"""Server-side dedup grouping — report only (fullbit-dedup spec; ADD 09 §2, ADR-011).

Builds ``dup_group`` / ``dup_member`` purely from the ``full_hash`` already stored on
``fs_entry`` rows by a full-bit ingest. It **never opens a file** — the bytes were hashed on
the owning host and only the hash crossed the wire (ADR-002). A group is formed only when two
or more rows share the **same full BLAKE3** (full-hash-confirmed; never size- or partial-only),
so no false-positive group can lead to a wrong deletion (ADD 09 §5, security_constraints).

Each group carries a **non-binding** suggested keeper ranked ``(1) oldest copy → (2) preferred
volume/path → (3) shortest path``, with the human-readable reason recorded (file-mgmt §5.5,
owner ruling #2). The service is strictly report-only: it writes the report tables and commits
nothing to any filesystem and calls into no remediation path (security_constraints: report-only
boundary).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.catalogue.models import DupGroup, DupMember, FsEntryRow, Volume
from fathom.core.query import escape_like
from fathom.logging import get_logger

_log = get_logger("fathom.core.dedup_service")

# Network filesystems whose files are a remote VIEW of bytes physically stored on another host (an
# NFS/SMB/sshfs mount). When the same file is full-hashed both natively (on the owning host) and
# through such a mount (on another host that mounts the export), the two share one ``full_hash`` and
# would group as a "duplicate" — but they are the SAME physical bytes, so deleting the mounted view
# frees nothing. A dedup member on a network-fs volume is therefore flagged as a cross-mount ALIAS
# and excluded from the group's reclaimable total (the false positive a fleet with NFS/SMB exports
# hits — e.g. nas-1 mounting node-1's NFS export; cross-mount dedup, ADR-032).
_NETWORK_FS: frozenset[str] = frozenset(
    {
        "nfs",
        "nfs4",
        "nfsd",
        "cifs",
        "smbfs",
        "smb",
        "smb2",
        "smb3",
        "sshfs",
        "fuse.sshfs",
        "fuse.rclone",
        "9p",
        "afs",
        "glusterfs",
        "ceph",
        "fuse.cephfs",
    }
)


def is_network_fs(fs_type: str) -> bool:
    """True when ``fs_type`` is a network mount (its files alias another host's native bytes)."""
    return fs_type.strip().lower() in _NETWORK_FS


# Flush + expunge the built groups every N so the SQLAlchemy unit-of-work never holds the pending
# state for the WHOLE estate at once. At scale (110k groups / 320k members on one rebuild) a single
# terminal flush kept ~half a GiB of per-object flush state resident and OOM-killed the 1 GiB API
# worker; flushing in bounded batches and detaching each keeps peak memory flat (the rebuild is
# also what the post-full-bit finalize runs). Small builds (tests) never reach a batch boundary.
_DEDUP_FLUSH_BATCH = 1000


@dataclass(frozen=True, slots=True)
class EntryRef:
    """The minimal fields the keeper ranking and dup_member rows need from an fs_entry."""

    entry_id: int
    host_id: int
    volume_id: int
    path: str
    size: int
    mtime: float
    ctime: float
    full_hash: str
    # The owning volume's filesystem type — drives cross-mount alias detection (a member on a
    # network fs is a remote view, not a reclaimable copy). "" when the volume row is missing.
    fs_type: str = ""


@dataclass(slots=True)
class DedupScope:
    """The scope a dedup run groups over (estate-wide by default).

    ``volume_ids`` (when set) restrict grouping to those volumes; ``path_prefix`` (with its
    ``volume_id``) restricts to a subtree. ``preferred_volume_ids`` / ``preferred_path_prefixes``
    feed the keeper rule's step (2) — the operator-configurable "preferred volume/path" list
    (design_questions #5). An empty scope means estate-wide.
    """

    volume_ids: frozenset[int] = field(default_factory=frozenset)
    path_prefix: str | None = None
    path_prefix_volume_id: int | None = None
    preferred_volume_ids: frozenset[int] = field(default_factory=frozenset)
    preferred_path_prefixes: tuple[str, ...] = ()

    def as_json(self) -> dict[str, object]:
        """A JSON-serialisable record of this scope for the ``dup_group.scope`` column."""
        return {
            "volume_ids": sorted(self.volume_ids),
            "path_prefix": self.path_prefix,
            "path_prefix_volume_id": self.path_prefix_volume_id,
            "preferred_volume_ids": sorted(self.preferred_volume_ids),
            "preferred_path_prefixes": list(self.preferred_path_prefixes),
        }


@dataclass(frozen=True, slots=True)
class KeeperChoice:
    """A chosen non-binding keeper and the human-readable reason it was chosen."""

    entry_id: int
    reason: str


KeeperRule = Callable[[Sequence[EntryRef], DedupScope], KeeperChoice]


def rank_oldest_then_preferred_then_shortest(
    members: Sequence[EntryRef], scope: DedupScope
) -> KeeperChoice:
    """Default non-binding keeper rule (ADR-011, file-mgmt §5.5).

    Rank: (1) oldest copy (min of mtime/ctime — the earliest the bytes are known to have
    existed), then (2) on a preferred volume/path, then (3) shortest path. The *reason* names
    the deciding rule so the UI can show "kept: oldest" / "kept: on preferred volume" etc.
    """

    def _oldest_ts(m: EntryRef) -> float:
        return min(m.mtime, m.ctime)

    # Never suggest keeping (or, downstream, removing on the basis of) a cross-mount alias: an alias
    # is a remote NFS/SMB view, not a deletable copy. Rank only the NATIVE copies when any exist.
    candidates = [m for m in members if not is_network_fs(m.fs_type)] or list(members)
    oldest_ts = min(_oldest_ts(m) for m in candidates)
    oldest = [m for m in candidates if _oldest_ts(m) == oldest_ts]
    if len(oldest) == 1:
        return KeeperChoice(entry_id=oldest[0].entry_id, reason="oldest copy")

    # Tie on age → prefer a preferred volume/path.
    preferred = [m for m in oldest if _is_preferred(m, scope)]
    pool = preferred if preferred else oldest
    reason = "oldest copy on preferred volume/path" if preferred else "oldest copy"

    # Final tiebreak → shortest path (fewest separators, then lexical).
    chosen = min(pool, key=lambda m: (m.path.count("/"), len(m.path), m.path))
    if len(pool) > 1:
        reason = f"{reason}, shortest path" if preferred else "shortest path"
    return KeeperChoice(entry_id=chosen.entry_id, reason=reason)


def _is_preferred(member: EntryRef, scope: DedupScope) -> bool:
    if member.volume_id in scope.preferred_volume_ids:
        return True
    return any(member.path.startswith(prefix) for prefix in scope.preferred_path_prefixes)


class DedupService:
    """Builds the report-only dup_group/dup_member tables from stored full hashes."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def build(
        self,
        *,
        scope: DedupScope | None = None,
        keeper: KeeperRule = rank_oldest_then_preferred_then_shortest,
        job_id: str | None = None,
        replace: bool = True,
    ) -> list[DupGroup]:
        """Group stored full hashes in ``scope`` into report-only dup groups.

        Args:
            scope: The volumes/subtree to group over (estate-wide when ``None``/empty), plus the
                preferred-volume/path hints for the keeper rule.
            keeper: The non-binding keeper rule (defaults to oldest→preferred→shortest).
            job_id: An opaque id recorded on each group linking it to the producing run.
            replace: Clear any previous groups for this scope before rebuilding (idempotent).

        Returns:
            The persisted (flushed) :class:`DupGroup` rows, each with its members and a
            non-binding suggested keeper + reason. No filesystem change is made (report-only).

        Prefer :meth:`rebuild` for an estate-scale run that only needs the count: this collects
        every group object for the caller, which at 110k+ groups is itself a few hundred MB.
        """
        return [
            group
            async for group in self._build_iter(
                scope=scope, keeper=keeper, job_id=job_id, replace=replace
            )
        ]

    async def rebuild(
        self,
        *,
        scope: DedupScope | None = None,
        keeper: KeeperRule = rank_oldest_then_preferred_then_shortest,
        job_id: str | None = None,
        replace: bool = True,
    ) -> int:
        """Rebuild the groups like :meth:`build`, but return only the COUNT (bounded memory).

        The post-full-bit finalize and the dedup worker only need "how many groups" — collecting
        every :class:`DupGroup` object (as :meth:`build` does) keeps a few hundred MB of ORM
        instances resident and OOM-killed the 1 GiB worker on a real estate. This consumes the
        same builder but discards each group after it is flushed, so peak memory stays flat.
        """
        count = 0
        async for _ in self._build_iter(scope=scope, keeper=keeper, job_id=job_id, replace=replace):
            count += 1
        return count

    async def _build_iter(
        self,
        *,
        scope: DedupScope | None,
        keeper: KeeperRule,
        job_id: str | None,
        replace: bool,
    ) -> AsyncIterator[DupGroup]:
        """Build + persist the groups, yielding each after its batch is flushed and detached.

        Shared by :meth:`build` (collects) and :meth:`rebuild` (counts). Groups are flushed and
        expunged in batches of ``_DEDUP_FLUSH_BATCH`` so the SQLAlchemy unit-of-work never holds
        the pending state for the whole estate; a consumer that discards each yielded group keeps
        peak memory flat.
        """
        scope = scope or DedupScope()
        if replace:
            await self._clear_scope(scope)

        rows = await self._load_hashed_entries(scope)
        # Group by (size, full_hash): identical bytes always share both; pairing size with the
        # hash makes a (vanishingly unlikely) cross-size hash collision impossible to mis-group.
        by_hash: dict[tuple[int, str], list[EntryRef]] = defaultdict(list)
        for ref in rows:
            by_hash[(ref.size, ref.full_hash)].append(ref)
        del rows  # the refs live on in by_hash; free the list container

        built = 0
        pending: list[DupGroup] = []
        for (size, full_hash), members in by_hash.items():
            if len(members) < 2:
                continue  # a single copy is not a duplicate — never grouped
            # Full-hash-confirmed by construction (grouped on the stored full_hash). Network-mount
            # members are cross-mount ALIASES (a remote view of bytes on another host), not separate
            # physical copies — so only NATIVE copies count toward reclaimable space, and with fewer
            # than two native copies the "duplicate" frees nothing (cross-mount dedup, ADR-032).
            native = [m for m in members if not is_network_fs(m.fs_type)]
            reclaimable = size * max(0, len(native) - 1)
            choice = keeper(members, scope)
            group = DupGroup(
                full_hash=full_hash,
                size=size,
                member_count=len(members),
                reclaimable_bytes=reclaimable,
                scope=scope.as_json(),
                job_id=job_id,
                suggested_keeper_entry_id=choice.entry_id,
                suggested_keeper_reason=choice.reason,
            )
            group.members = [
                DupMember(
                    entry_id=m.entry_id,
                    host_id=m.host_id,
                    volume_id=m.volume_id,
                    path=m.path,
                    is_mount_alias=is_network_fs(m.fs_type),
                )
                for m in members
            ]
            self._session.add(group)
            pending.append(group)
            if len(pending) >= _DEDUP_FLUSH_BATCH:
                await self._flush_and_detach(pending)
                for flushed in pending:
                    yield flushed
                built += len(pending)
                pending = []

        if pending:
            await self._flush_and_detach(pending)
            for flushed in pending:
                yield flushed
            built += len(pending)
        _log.info(
            "dedup groups built",
            extra={"groups": built, "job_id": job_id, "scope": scope.as_json()},
        )

    async def _flush_and_detach(self, pending: list[DupGroup]) -> None:
        """Persist a batch of built groups, then expunge them to release the unit-of-work state.

        The rows are committed by the surrounding transaction; expunging the just-flushed groups
        (and their members) only detaches the Python instances from the session identity map, so
        SQLAlchemy stops tracking pending/flush state for them. Callers still hold the (now
        detached) objects — their already-loaded column values and the explicitly-set ``members``
        collection remain readable; only a fresh lazy-load would fail, which the read paths avoid.
        """
        await self._session.flush()
        for group in pending:
            for member in group.members:
                self._session.expunge(member)
            self._session.expunge(group)

    async def _clear_scope(self, scope: DedupScope) -> None:
        """Delete prior groups for this scope (members first) so a rebuild is idempotent.

        A scope is matched by its serialised JSON; with no prior identical-scope run this is a
        no-op. Cross-scope groups are left intact. The member delete keys off a **scalar subquery**
        over the scope, not a materialised id list — an estate rebuild clears 110k+ groups, and a
        ``group_id IN (<110k literals>)`` blows PostgreSQL's 32767 bind-parameter ceiling.
        """
        scope_json = scope.as_json()
        prior_ids = select(DupGroup.id).where(DupGroup.scope == scope_json).scalar_subquery()
        await self._session.execute(delete(DupMember).where(DupMember.group_id.in_(prior_ids)))
        await self._session.execute(delete(DupGroup).where(DupGroup.scope == scope_json))

    async def _load_hashed_entries(self, scope: DedupScope) -> list[EntryRef]:
        """Load the full-bit-hashed fs_entry rows in scope (never opens any file)."""
        stmt = (
            select(
                FsEntryRow.id,
                FsEntryRow.host_id,
                FsEntryRow.volume_id,
                FsEntryRow.path,
                FsEntryRow.size_logical,
                FsEntryRow.mtime,
                FsEntryRow.ctime,
                FsEntryRow.full_hash,
                # The owning volume's fs_type → cross-mount alias detection. Outer-join so a
                # (theoretical) missing volume row never drops a hashed entry; treated as native.
                Volume.fs_type.label("fs_type"),
            )
            .join(Volume, Volume.id == FsEntryRow.volume_id, isouter=True)
            .where(
                FsEntryRow.full_hash.is_not(None),
                # Never group a not-present (removed) entry or a directory: a deleted file could
                # otherwise be grouped and even suggested as the keeper, and a hashed dir is not a
                # reclaimable file. Mirrors the provider-hash dedup path (provider_dedup.py).
                FsEntryRow.present.is_(True),
                FsEntryRow.is_dir.is_(False),
            )
        )
        if scope.volume_ids:
            stmt = stmt.where(FsEntryRow.volume_id.in_(scope.volume_ids))
        if scope.path_prefix is not None and scope.path_prefix_volume_id is not None:
            like = escape_like(scope.path_prefix.rstrip("/")) + "/%"
            stmt = stmt.where(
                FsEntryRow.volume_id == scope.path_prefix_volume_id,
                (FsEntryRow.path == scope.path_prefix) | FsEntryRow.path.like(like, escape="\\"),
            )
        result = await self._session.execute(stmt)
        return [
            EntryRef(
                entry_id=row.id,
                host_id=row.host_id,
                volume_id=row.volume_id,
                path=row.path,
                size=row.size_logical,
                mtime=row.mtime,
                ctime=row.ctime,
                full_hash=row.full_hash,
                fs_type=row.fs_type or "",
            )
            for row in result
        ]
