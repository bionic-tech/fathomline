"""Incremental reconciliation — presence markers + the change-log feed (ADR-006, ADD 09 §2).

The agent's change feed (``zfs diff`` / ``fanotify`` / re-stat) sends a *delta*: a batch of
created-or-modified entries plus the inodes it observed *removed*. This module turns that delta
into catalogue truth without ever inferring deletion from snapshot staleness (the incremental
owner ruling):

* A re-appearing or changed entry is upserted by the existing idempotent
  ``(host_id, volume_id, inode)`` path; this module classifies it CREATE (new or resurrected
  row) vs MODIFY (size/mtime changed) so the churn feed is accurate.
* An ``inode`` in ``removed_inodes`` flips its row to ``present=False, removed_at=<ts>`` — the
  row is **kept** (a subtree's history survives the file that produced it) and a DELETE churn
  row is recorded. The same inode re-appearing later resurrects the row to ``present=True``.
* A *rename* is a cheap path update where the feed can detect it (same inode, new path): that is
  just a MODIFY upsert on the existing inode. Where it cannot be detected it surfaces as a
  DELETE of the old path plus a CREATE of the new — exactly the "rename = cheap path update
  where detectable else DELETE+CREATE" ruling, resolved by the feed, not here.

Churn rows are written only when the volume's ``change_log_enabled`` is set (default ON,
per-volume). They are append-only and retention-capped by :func:`prune_change_log`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

from sqlalchemy import CursorResult, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.catalogue.models import ChangeLog, FsEntryRow, Volume
from fathom.logging import get_logger

_log = get_logger("fathom.core.incremental")

ChangeType = Literal["create", "modify", "delete"]
# The closed vocabulary the churn feed and the ChangeOut wire schema share.
CHANGE_TYPES: frozenset[str] = frozenset({"create", "modify", "delete"})

# Default churn retention: 90 days (incremental owner ruling). Independent of the snapshot
# 1-5y retention (ADD 09 §10 open-question #1, resolved to 90d here).
CHANGE_LOG_RETENTION_DAYS = 90


@dataclass(frozen=True, slots=True)
class PriorState:
    """The pre-reconcile state of one catalogue entry, keyed by (dev, inode)."""

    present: bool
    mtime: float
    size_logical: int
    path: str


@dataclass(slots=True)
class ReconcileResult:
    """Outcome of reconciling one delta against the catalogue."""

    removed: int = 0
    changes_logged: int = 0


class ChangeReconciler:
    """Classifies a delta into churn rows and applies the presence markers (ADR-006).

    Runs inside the caller's ingest transaction (the same :class:`AsyncSession`); it never
    commits. The classification reads the prior ``(present, mtime, size_logical)`` of the batch's
    inodes *before* the upsert overwrites them, so CREATE/MODIFY are distinguished correctly.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def snapshot_prior(
        self, *, host_id: int, volume_id: int, inodes: list[int]
    ) -> dict[tuple[int, int], PriorState]:
        """Read the pre-upsert state of ``inodes`` so CREATE vs MODIFY can be told apart.

        Returns a map of ``(dev, inode) -> prior state`` for the rows that already exist; absent
        keys are new (CREATE). Keyed on (dev, inode) — not inode alone — because the catalogue
        identity is ``(host, volume, dev, inode)`` and a cross_mounts walk spans child datasets
        that reuse low inode numbers, so inode alone collides across devices and would misclassify
        a CREATE as a MODIFY (or vice versa). Bounded by the batch size (the caller validates that).
        """
        if not inodes:
            return {}
        rows = (
            await self._session.execute(
                select(
                    FsEntryRow.dev,
                    FsEntryRow.inode,
                    FsEntryRow.present,
                    FsEntryRow.mtime,
                    FsEntryRow.size_logical,
                    FsEntryRow.path,
                ).where(
                    FsEntryRow.host_id == host_id,
                    FsEntryRow.volume_id == volume_id,
                    FsEntryRow.inode.in_(inodes),
                )
            )
        ).all()
        return {
            (r.dev, r.inode): PriorState(
                present=r.present, mtime=r.mtime, size_logical=r.size_logical, path=r.path
            )
            for r in rows
        }

    async def reconcile(
        self,
        *,
        host_id: int,
        volume_id: int,
        rows: list[dict[str, object]],
        prior: dict[tuple[int, int], PriorState],
        removed_inodes: list[int],
        log_changes: bool,
        now: datetime | None = None,
    ) -> ReconcileResult:
        """Apply deletions + presence resurrection and emit churn rows for ``rows``.

        Args:
            host_id / volume_id: The resolved (server-side) identity of this batch.
            rows: The vetted upsert rows (already written by the ingest upsert); each carries
                ``inode``/``path``/``size_logical``/``mtime``.
            prior: The pre-upsert state from :meth:`snapshot_prior`.
            removed_inodes: Inodes the feed observed removed (explicit deletions).
            log_changes: Whether the volume's churn feed is enabled (writes change_log rows).
            now: Injectable timestamp (tests). Defaults to ``datetime.now(UTC)``.

        Returns:
            A :class:`ReconcileResult` with the removal count and churn-row count.
        """
        when = now or datetime.now(tz=UTC)
        result = ReconcileResult()

        # 1. CREATE / MODIFY classification for the upserted rows (history feed).
        churn: list[ChangeLog] = []
        for row in rows:
            inode = cast(int, row["inode"])
            path = cast(str, row["path"])
            new_size = cast(int, row["size_logical"])
            new_mtime = cast(float, row["mtime"])
            # dev defaults to 0 (the single-filesystem default, matching FsEntryRow.dev) when a
            # caller omits it; real ingest rows always carry it, so cross-dataset inode collisions
            # are keyed apart exactly as the catalogue identity (host, volume, dev, inode) is.
            before = prior.get((cast(int, row.get("dev", 0)), inode))
            change = self._classify(before, new_size=new_size, new_mtime=new_mtime)
            if change is None:
                continue  # unchanged (re-stat of an identical present row) → no churn row
            old_size = before.size_logical if before is not None else 0
            churn.append(
                ChangeLog(
                    volume_id=volume_id,
                    path=path,
                    change_type=change,
                    size_delta=new_size - old_size,
                )
            )

        # 2. DELETE: flip removed inodes to not-present, keep the row, record the size freed.
        result.removed = await self._mark_removed(
            host_id=host_id, volume_id=volume_id, removed_inodes=removed_inodes, when=when
        )
        if log_changes:
            churn.extend(
                await self._removal_churn(
                    host_id=host_id, volume_id=volume_id, removed_inodes=removed_inodes, when=when
                )
            )

        if log_changes and churn:
            self._session.add_all(churn)
            result.changes_logged = len(churn)
        await self._session.flush()
        return result

    @staticmethod
    def _classify(
        before: PriorState | None, *, new_size: int, new_mtime: float
    ) -> ChangeType | None:
        """CREATE for a new/resurrected row, MODIFY on size/mtime change, else None (no churn)."""
        if before is None or not before.present:
            # Brand-new inode, or a previously-removed inode that has re-appeared (resurrection):
            # both are a CREATE from the churn feed's point of view.
            return "create"
        if before.size_logical != new_size or before.mtime != new_mtime:
            return "modify"
        return None

    async def _mark_removed(
        self,
        *,
        host_id: int,
        volume_id: int,
        removed_inodes: list[int],
        when: datetime,
    ) -> int:
        """Flip live rows for ``removed_inodes`` to ``present=False`` and return the count.

        Only rows that are currently present are flipped (so a duplicate removal in a later batch
        is a no-op and does not double-count or re-stamp ``removed_at``).

        KNOWN LIMITATION (tracked; review P3): removals are keyed on ``inode`` alone, whereas the
        catalogue identity (and the CREATE/MODIFY classification above) is ``(dev, inode)``. On a
        ``cross_mounts`` volume spanning ZFS child datasets that reuse low inode numbers, a removal
        batch could in principle flip the wrong device's row to ``present=False`` (it resurrects on
        the next walk, so it is self-healing, never data loss). The correct fix is a wire change —
        the agent's incremental delta carrying ``(dev, inode)`` pairs — done deliberately (with its
        own migration/contract bump) rather than inferred here; ``removed_inodes`` stays inode-only
        until then.
        """
        if not removed_inodes:
            return 0
        stmt = (
            update(FsEntryRow)
            .where(
                FsEntryRow.host_id == host_id,
                FsEntryRow.volume_id == volume_id,
                FsEntryRow.inode.in_(removed_inodes),
                FsEntryRow.present.is_(True),
            )
            .values(present=False, removed_at=when)
        )
        res = cast(CursorResult[object], await self._session.execute(stmt))
        return res.rowcount or 0

    async def _removal_churn(
        self,
        *,
        host_id: int,
        volume_id: int,
        removed_inodes: list[int],
        when: datetime,
    ) -> list[ChangeLog]:
        """Build a DELETE churn row per removed path (size_delta = -freed bytes).

        Reads the (now not-present) rows back so the churn row carries the real path + freed
        size. Only rows whose ``removed_at == when`` are included so a no-op duplicate removal
        emits no churn row.
        """
        if not removed_inodes:
            return []
        rows = (
            await self._session.execute(
                select(FsEntryRow.path, FsEntryRow.size_logical).where(
                    FsEntryRow.host_id == host_id,
                    FsEntryRow.volume_id == volume_id,
                    FsEntryRow.inode.in_(removed_inodes),
                    FsEntryRow.removed_at == when,
                )
            )
        ).all()
        return [
            ChangeLog(
                volume_id=volume_id,
                path=r.path,
                change_type="delete",
                size_delta=-r.size_logical,
            )
            for r in rows
        ]


async def prune_change_log(
    session: AsyncSession,
    *,
    retention_days: int = CHANGE_LOG_RETENTION_DAYS,
    now: datetime | None = None,
) -> int:
    """Delete churn rows older than ``retention_days`` and return how many were removed.

    The change_log is retention-capped (incremental owner ruling: 90-day retention) so the churn
    feed stays bounded at estate scale. Runs in the caller's transaction; the
    :class:`~fathom.workers.retention.RetentionWorker` calls it on a schedule.
    """
    if retention_days < 1:
        raise ValueError("retention_days must be >= 1")
    cutoff = (now or datetime.now(tz=UTC)) - timedelta(days=retention_days)
    res = cast(
        CursorResult[object],
        await session.execute(delete(ChangeLog).where(ChangeLog.ts < cutoff)),
    )
    removed = res.rowcount or 0
    if removed:
        _log.info(
            "change_log pruned",
            extra={"removed": removed, "retention_days": retention_days},
        )
    return removed


async def volume_feed_enabled(session: AsyncSession, volume: Volume) -> bool:
    """Return whether ``volume``'s churn feed is enabled (default ON; explicit-off respected)."""
    return bool(volume.change_log_enabled)
