"""Ingest service — upsert agent batches into the catalogue (ADD 02 §7.2, ADD 09).

The server is the trust boundary. It re-derives the host identity from the mTLS
fingerprint (never the body), and independently re-enforces that every entry path lies
within the volume mountpoint — the agent's own scope check is necessary but not trusted
(AR-0012). Writes are idempotent on ``(host_id, volume_id, dev, inode)`` with a change guard on
``(mtime, size_logical)`` so a resumed push never duplicates rows. ``dev`` (st_dev) is in the key
so cross-dataset inode collisions (ZFS child datasets reuse low inode numbers) don't clobber.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePath

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.api.schemas import EntryFrame, IngestBatch, IngestResult
from fathom.core.catalogue.models import FsEntryRow, Host, Snapshot, Volume
from fathom.core.incremental import (
    ChangeReconciler,
    PriorState,
    ReconcileResult,
    volume_feed_enabled,
)
from fathom.logging import get_logger
from fathom.security.paths import PathSafetyError, validate_config_path
from fathom.security.winpaths import validate_windows_config_path

_log = get_logger("fathom.core.ingest")


class IngestError(RuntimeError):
    """Raised when a batch cannot be accepted (bad identity, scope, or size)."""


@dataclass(slots=True)
class _Accepted:
    rows: list[dict[str, object]]
    rejected: int


@dataclass(slots=True)
class _DeferredReconcile:
    """Holds the pre-upsert state so the churn/removal apply runs after the upsert.

    CREATE-vs-MODIFY classification needs the entries' *prior* ``(present, mtime, size)``, which
    the upsert overwrites; this captures it up front and applies the change-log + removal markers
    once the new rows are in place. A full-bit batch yields ``reconciler is None`` → a zero apply.
    """

    reconciler: ChangeReconciler | None
    host_id: int = 0
    volume_id: int = 0
    rows: list[dict[str, object]] = field(default_factory=list)
    prior: dict[tuple[int, int], PriorState] = field(default_factory=dict)
    # Each key is (dev, inode) for a precise removal, or (None, inode) for a legacy inode-only one.
    removed_keys: list[tuple[int | None, int]] = field(default_factory=list)
    log_changes: bool = False

    async def apply(self) -> ReconcileResult:
        """Emit churn rows + flip removed entries to not-present; report counts."""
        if self.reconciler is None:
            return ReconcileResult()
        return await self.reconciler.reconcile(
            host_id=self.host_id,
            volume_id=self.volume_id,
            rows=self.rows,
            prior=self.prior,
            removed_keys=self.removed_keys,
            log_changes=self.log_changes,
        )


# A native Windows agent (ADR-027) sends drive-letter (``C:\...``) or UNC (``\\host\share``)
# mountpoints and entry paths. The POSIX validator rejects those outright (they are not absolute on
# the Linux server), so the server-side trust-boundary re-validation (AR-0012) must dispatch on the
# path shape to the matching *hardened* validator — POSIX paths still go through the POSIX rules
# unchanged; only Windows-shaped paths take the Windows rules (which fail closed on ADS, reserved
# device names, traversal, etc. — ADR-027 W1).
_WINDOWS_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")


def _validate_agent_path(text: str) -> PurePath:
    """Validate an agent-supplied absolute path with the rules matching its platform (AR-0012).

    Both validators fail closed on traversal / unsafe input; this only chooses *which* ruleset
    applies, by path shape. A POSIX agent can never produce a Windows-shaped string and vice versa,
    so the dispatch cannot be used to slip a POSIX path past the POSIX checks.
    """
    if _WINDOWS_PATH.match(text):
        return validate_windows_config_path(text)
    return validate_config_path(text)


def _path_depth(mount: PurePath, candidate: PurePath) -> int:
    """Depth of ``candidate`` below ``mount`` (the mount itself is depth 0). Flavour-agnostic."""
    return len(candidate.parts) - len(mount.parts)


def _vet_entries(volume_mountpoint: str, entries: list[EntryFrame], *, fullbit: bool) -> _Accepted:
    """Re-validate every entry path server-side; drop (don't trust) anything out of scope.

    On a ``fullbit`` batch the content hashes are carried onto the row (and ``hashed_at`` is
    stamped server-side); a metadata batch omits them entirely so the existing catalogue hash
    columns are left untouched by the upsert (fullbit-dedup data_model_changes).
    """
    mount = _validate_agent_path(volume_mountpoint)
    hashed_at = datetime.now(tz=UTC) if fullbit else None
    rows: list[dict[str, object]] = []
    rejected = 0
    for e in entries:
        try:
            candidate = _validate_agent_path(e.path)
        except PathSafetyError:
            rejected += 1
            continue
        # Must be the volume root or strictly within it — defeats traversal / cross-volume.
        if candidate != mount and mount not in candidate.parents:
            rejected += 1
            continue
        row: dict[str, object] = {
            "name": e.name,
            "path": str(candidate),
            "depth": _path_depth(mount, candidate),
            "is_dir": e.is_dir,
            "is_symlink": e.is_symlink,
            "size_logical": e.size_logical,
            "size_on_disk": e.size_on_disk,
            "mtime": e.mtime,
            "ctime": e.ctime,
            "uid": e.uid,
            "gid": e.gid,
            "inode": e.inode,
            "dev": e.dev,
            "flags": e.flags,
            # Provider-attested hash (ADR-028 phase 2): rides ANY batch — unlike full_hash it is
            # NOT agent-computed (the cloud provider computed it; rclone relays it without a
            # download), so it is not gated on fullbit. It lives in its own columns, is never
            # conflated with full_hash, and feeds only the report-only provider-hash grouping —
            # NEVER remediation (which keys on the content-verified full_hash). A forged value can
            # therefore only mislead an informational report, never drive a destructive action.
            "provider_hash": e.provider_hash,
            "provider_hash_algo": e.provider_hash_algo,
        }
        if fullbit:
            # Trust hashes only on a fullbit batch; the server stamps hashed_at itself.
            row["partial_hash"] = e.partial_hash
            row["full_hash"] = e.full_hash
            row["hashed_at"] = hashed_at
        rows.append(row)
    return _Accepted(rows=rows, rejected=rejected)


class IngestService:
    """Upserts batches into the catalogue within a caller-managed transaction."""

    def __init__(self, session: AsyncSession, *, max_batch: int = 5000) -> None:
        self._session = session
        self._max_batch = max_batch

    async def ingest(self, batch: IngestBatch, *, cert_fingerprint: str) -> IngestResult:
        """Accept a batch from the authenticated host and upsert its entries."""
        if len(batch.entries) > self._max_batch:
            raise IngestError(f"batch of {len(batch.entries)} exceeds max {self._max_batch}")
        # Removals are bounded by the same per-batch cap (DoS guard, AR-0012): a forged batch cannot
        # blow up the reconcile step with an unbounded removal list. Apply the cap to whichever
        # removal list is larger ((dev,inode) ``removed`` or legacy inode-only ``removed_inodes``).
        removed_count = max(len(batch.removed), len(batch.removed_inodes))
        if removed_count > self._max_batch:
            raise IngestError(f"removals of {removed_count} exceeds max {self._max_batch}")

        # AR-0012 (ADR-029): the volume mountpoint is agent-supplied — re-vet it server-side and
        # refuse a non-canonical / traversing one. Otherwise a ``..`` mountpoint (e.g.
        # /sftp/h/../../etc) would normalise into a real local namespace and alias another volume's
        # entries (the per-entry containment check below uses the *normalised* mount, so the escaped
        # entries would pass). The agent config and deploy bundle reject this too, but the server
        # must not trust them. Fail closed → 422.
        try:
            canonical_mount = str(_validate_agent_path(batch.volume.mountpoint))
        except PathSafetyError as exc:
            raise IngestError(f"unsafe volume mountpoint: {batch.volume.mountpoint!r}") from exc
        if canonical_mount != batch.volume.mountpoint:
            raise IngestError(
                f"non-canonical volume mountpoint {batch.volume.mountpoint!r} "
                f"(normalises to {canonical_mount!r}) — refused (AR-0012/ADR-029)"
            )

        host = await self._upsert_host(batch, cert_fingerprint)
        volume = await self._upsert_volume(host, batch)
        snapshot = await self._resolve_snapshot(host, volume, batch)

        fullbit = batch.mode == "fullbit"
        accepted = _vet_entries(volume.mountpoint, batch.entries, fullbit=fullbit)
        if accepted.rejected:
            _log.warning(
                "ingest dropped out-of-scope entries",
                extra={
                    "host_id": host.id,
                    "volume_id": volume.id,
                    "rejected": accepted.rejected,
                },
            )

        # Build the precise removal keys. A modern agent sends ``removed`` ([(dev, inode)] pairs);
        # a legacy agent sends only ``removed_inodes`` (inode-only), which we carry as (None, inode)
        # so the reconcile falls back to an inode-only match for exactly those keys (a
        # backward-compatible wire change). ``removed`` wins when both are present.
        if batch.removed:
            removed_keys: list[tuple[int | None, int]] = [(r.dev, r.inode) for r in batch.removed]
        else:
            removed_keys = [(None, i) for i in batch.removed_inodes]

        # Incremental reconciliation runs on a metadata batch only: a full-bit batch re-hashes
        # existing files (it neither creates nor removes entries), so it carries no removals and
        # must not churn the feed (incremental: removals are an explicit feed signal). Capture the
        # pre-upsert state of the touched inodes *before* the upsert overwrites them so CREATE vs
        # MODIFY is classified correctly.
        reconcile = await self._reconcile_delta(
            host_id=host.id,
            volume=volume,
            rows=accepted.rows,
            removed_keys=removed_keys,
            fullbit=fullbit,
        )

        if accepted.rows:
            await self._upsert_entries(
                host.id, volume.id, snapshot.id, accepted.rows, fullbit=fullbit
            )

        result = await reconcile.apply()
        return IngestResult(
            snapshot_id=snapshot.id,
            host_id=host.id,
            volume_id=volume.id,
            entries_received=len(accepted.rows),
            entries_rejected=accepted.rejected,
            entries_removed=result.removed,
            changes_logged=result.changes_logged,
        )

    async def _reconcile_delta(
        self,
        *,
        host_id: int,
        volume: Volume,
        rows: list[dict[str, object]],
        removed_keys: list[tuple[int | None, int]],
        fullbit: bool,
    ) -> _DeferredReconcile:
        """Capture pre-upsert state now; defer the churn/removal apply until after the upsert.

        On a full-bit batch this is a no-op (full-bit carries no removals and must not churn the
        feed): the returned object's :meth:`_DeferredReconcile.apply` reports zeros. On a metadata
        batch it snapshots the touched inodes' prior state so CREATE-vs-MODIFY is correct, then the
        deferred apply (run after the upsert has written the new rows) emits the churn rows and
        flips removed inodes to not-present.
        """
        if fullbit:
            return _DeferredReconcile(reconciler=None)
        reconciler = ChangeReconciler(self._session)
        inodes = [int(r["inode"]) for r in rows]  # type: ignore[call-overload]
        prior = await reconciler.snapshot_prior(host_id=host_id, volume_id=volume.id, inodes=inodes)
        log_changes = await volume_feed_enabled(self._session, volume)
        return _DeferredReconcile(
            reconciler=reconciler,
            host_id=host_id,
            volume_id=volume.id,
            rows=rows,
            prior=prior,
            removed_keys=removed_keys,
            log_changes=log_changes,
        )

    async def _upsert_host(self, batch: IngestBatch, cert_fingerprint: str) -> Host:
        existing = (
            await self._session.execute(
                select(Host).where(Host.cert_fingerprint == cert_fingerprint)
            )
        ).scalar_one_or_none()
        if existing is None:
            existing = Host(name=batch.host.name, cert_fingerprint=cert_fingerprint)
            self._session.add(existing)
        existing.os = batch.host.os
        existing.agent_version = batch.host.agent_version
        # Persist hardware facts only when the agent reported them (ADR-037) — never overwrite
        # previously known facts with null from a pre-facts agent.
        if batch.host.facts is not None:
            existing.facts = batch.host.facts.model_dump()
        existing.last_seen = datetime.now(tz=UTC)
        await self._session.flush()
        return existing

    async def _upsert_volume(self, host: Host, batch: IngestBatch) -> Volume:
        v = batch.volume
        existing = (
            await self._session.execute(
                select(Volume).where(Volume.host_id == host.id, Volume.mountpoint == v.mountpoint)
            )
        ).scalar_one_or_none()
        if existing is None:
            existing = Volume(
                host_id=host.id,
                mountpoint=v.mountpoint,
                fs_type=v.fs_type,
                device=v.device,
                transport=v.transport,
            )
            self._session.add(existing)
        existing.fs_type = v.fs_type
        existing.device = v.device
        existing.transport = v.transport
        existing.raid_role = v.raid_role
        existing.pool = v.pool
        existing.dataset = v.dataset
        existing.display_name = v.display_name  # human label for synthetic remote mounts (ADR-029)
        existing.total = v.total
        existing.used = v.used
        existing.free = v.free
        existing.updated_at = datetime.now(tz=UTC)
        await self._session.flush()
        return existing

    async def _resolve_snapshot(self, host: Host, volume: Volume, batch: IngestBatch) -> Snapshot:
        if batch.snapshot_id is not None:
            snap = await self._session.get(Snapshot, batch.snapshot_id)
            if snap is None or snap.host_id != host.id or snap.volume_id != volume.id:
                raise IngestError("snapshot_id does not belong to this host/volume")
            return snap
        snap = Snapshot(host_id=host.id, volume_id=volume.id, mode=batch.mode)
        self._session.add(snap)
        await self._session.flush()
        return snap

    async def _upsert_entries(
        self,
        host_id: int,
        volume_id: int,
        snapshot_id: int,
        rows: list[dict[str, object]],
        *,
        fullbit: bool,
    ) -> None:
        for row in rows:
            row["host_id"] = host_id
            row["volume_id"] = volume_id
            row["last_seen_snapshot_id"] = snapshot_id
            if not fullbit:
                # A row in a metadata batch came from a walk → it is present on disk now. Setting
                # present/removed_at on insert makes a brand-new row present, and the conflict
                # branch below resurrects a previously-removed row (incremental: a re-appearing
                # inode resurrects to present). A full-bit batch leaves presence untouched.
                row["present"] = True
                row["removed_at"] = None

        dialect = self._session.bind.dialect.name if self._session.bind else "sqlite"
        insert = pg_insert if dialect == "postgresql" else sqlite_insert
        stmt = insert(FsEntryRow).values(rows)
        set_: dict[str, object] = {
            "path": stmt.excluded.path,
            "name": stmt.excluded.name,
            "depth": stmt.excluded.depth,
            "is_dir": stmt.excluded.is_dir,
            "is_symlink": stmt.excluded.is_symlink,
            "size_logical": stmt.excluded.size_logical,
            "size_on_disk": stmt.excluded.size_on_disk,
            "mtime": stmt.excluded.mtime,
            "ctime": stmt.excluded.ctime,
            "uid": stmt.excluded.uid,
            "gid": stmt.excluded.gid,
            "flags": stmt.excluded.flags,
            "last_seen_snapshot_id": stmt.excluded.last_seen_snapshot_id,
            # Provider-attested hash refreshes on the same change-guarded conflict as the rest of
            # the metadata (it is provider metadata, not an agent content read — ADR-028 phase 2).
            "provider_hash": stmt.excluded.provider_hash,
            "provider_hash_algo": stmt.excluded.provider_hash_algo,
        }
        if fullbit:
            # A full-bit batch is the ONLY writer of the hash columns; a metadata batch never
            # touches them, so a re-stat that flips mtime/size does not clear a stored hash on a
            # metadata pass (fullbit-dedup data_model_changes).
            set_["partial_hash"] = stmt.excluded.partial_hash
            set_["full_hash"] = stmt.excluded.full_hash
            set_["hashed_at"] = stmt.excluded.hashed_at
        else:
            # Resurrect on conflict: a re-appearing inode is present again (incremental).
            set_["present"] = stmt.excluded.present
            set_["removed_at"] = stmt.excluded.removed_at
        # On a full-bit batch, an unchanged (mtime,size) row would be skipped by the change guard
        # — but its hash is exactly what we came to set, so a fullbit upsert ignores the guard. On
        # a metadata batch the guard also fires when the stored row is not-present, so a file that
        # re-appears byte-for-byte identical is still resurrected to present (incremental).
        guard = (
            None
            if fullbit
            else (stmt.excluded.mtime != FsEntryRow.mtime)
            | (stmt.excluded.size_logical != FsEntryRow.size_logical)
            | (FsEntryRow.present.is_(False))
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[
                FsEntryRow.host_id,
                FsEntryRow.volume_id,
                FsEntryRow.dev,
                FsEntryRow.inode,
            ],
            set_=set_,
            where=guard,
        )
        await self._session.execute(stmt)
