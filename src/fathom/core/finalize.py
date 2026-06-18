"""Rollup finalize service — recompute subtree sizes for a host's freshly-ingested volumes.

The agent push lands raw ``fs_entry`` rows; nothing in the ingest path computes the
``subtree_rollup`` totals the UI tree/treemap read (ADD 09 §8 — "scheduled rollups for instant
subtree sizes"). This service closes that loop: after an agent has drained its staged deltas it
calls a single finalize, and the server recomputes the baseline rollup for exactly the volumes
that host touched since their last finalize.

Finalize is also where the **report-only dedup grouping** is rebuilt. A full-bit pass stages
``full_hash`` values that ride the same drain as the metadata deltas, but nothing groups them into
``dup_group``/``dup_member`` rows on its own — so without a trigger the ``/duplicates`` view stays
empty even after content has been hashed. ADD 02 §7.1 specifies an arq ``dedup`` queue for that
grouping but also allows ":class:`DedupService` invoked synchronously post-ingest as an interim"
until the broker is provisioned. The post-drain finalize the agent already makes is exactly that
post-ingest hook: when any full hashes are present, finalize rebuilds the estate-wide dup groups in
the **same transaction** as the rollups (report-only — it opens no file and changes no filesystem).

The trust boundary is identical to ingest (AR-0012): the calling host's identity is its mTLS
cert fingerprint, never the request body, and finalize only ever touches **that host's** volumes.
"touched since the last finalize" is derived from the append-only catalogue itself — a volume is
stale iff it has a ``snapshot`` newer than its most recent ``subtree_rollup`` (or has no rollup
yet) — so no extra bookkeeping column is needed and a re-run is a cheap no-op once a volume is
already current.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.catalogue.models import FsEntryRow, Host, Snapshot, SubtreeRollup, Volume
from fathom.core.dedup_service import DedupScope, DedupService
from fathom.core.rollup import RollupService
from fathom.logging import get_logger

_log = get_logger("fathom.core.finalize")


@dataclass(slots=True)
class FinalizeResult:
    """Outcome of a finalize call: which of the host's volumes were recomputed.

    ``dup_groups`` is the number of report-only duplicate groups the estate-wide dedup rebuild
    produced (``0`` when no full hashes exist yet, i.e. metadata-only deployments — the common
    case, so a non-full-bit run is wholly unchanged).
    """

    host_id: int
    volume_ids: list[int]
    rollup_rows: int
    dup_groups: int = 0


class FinalizeService:
    """Recompute rollups for the calling host's stale volumes within the caller's transaction.

    When ``build_dedup`` is set (the default), a finalize that follows a full-bit ingest also
    rebuilds the report-only duplicate groups so the ``/duplicates`` read surface reflects the
    freshly-hashed content. A deployment that drives dedup from the arq queue can disable this
    inline rebuild without losing the rollup finalize.
    """

    def __init__(self, session: AsyncSession, *, build_dedup: bool = True) -> None:
        self._session = session
        self._rollups = RollupService(session)
        self._build_dedup = build_dedup

    async def finalize_host(self, *, cert_fingerprint: str) -> FinalizeResult:
        """Recompute the baseline rollup for every volume this host has touched since last time.

        Returns the recomputed volume ids, the total rollup rows written, and the number of
        report-only dup groups rebuilt. A host with nothing new since its previous finalize
        recomputes nothing (empty result) — the call is idempotent and cheap to repeat.
        """
        host = (
            await self._session.execute(
                select(Host).where(Host.cert_fingerprint == cert_fingerprint)
            )
        ).scalar_one_or_none()
        # An unknown fingerprint has ingested nothing yet — there is simply nothing to finalize.
        # (The mTLS/proxy boundary already authenticated the caller; this is not an authz failure.)
        if host is None:
            return FinalizeResult(host_id=0, volume_ids=[], rollup_rows=0)

        volume_ids = await self._stale_volume_ids(host.id)
        total_rows = 0
        for volume_id in volume_ids:
            total_rows += await self._rollups.recompute_full(volume_id)
            await self._finalize_snapshot_stats(volume_id)
        dup_groups = await self._rebuild_dedup(host.id)
        _log.info(
            "finalize recomputed rollups",
            extra={
                "host_id": host.id,
                "volumes": len(volume_ids),
                "rollup_rows": total_rows,
                "dup_groups": dup_groups,
            },
        )
        return FinalizeResult(
            host_id=host.id,
            volume_ids=list(volume_ids),
            rollup_rows=total_rows,
            dup_groups=dup_groups,
        )

    async def _finalize_snapshot_stats(self, volume_id: int) -> None:
        """Stamp the volume's still-open snapshots with the just-computed totals + a finish time.

        Ingest opens a ``snapshot`` row per scan but cannot know the volume's final entry count /
        on-disk size until the bottom-up rollup exists. So finalize — which has just rebuilt the
        rollup — copies the root rollup's totals (the volume mountpoint row) onto every snapshot of
        this volume that is still unfinished, and marks them finished. This populates the Scans
        view's ``Entries`` / ``On-disk`` / ``Finished`` columns (ADD 09 §4); without it they stay
        0/null. Only **unfinished** snapshots are touched, so a re-finalize never rewrites an
        already-closed scan's record. In the normal flow finalize runs right after each scan's
        drain, so exactly that scan's snapshot is open; a batch-all-then-finalize-once flow closes
        them together. A volume with no rollup root (nothing scanned) leaves snapshots untouched.
        """
        volume = await self._session.get(Volume, volume_id)
        if volume is None:
            return
        root = (
            await self._session.execute(
                select(SubtreeRollup.total_size_on_disk, SubtreeRollup.file_count).where(
                    SubtreeRollup.volume_id == volume_id,
                    SubtreeRollup.path == volume.mountpoint,
                )
            )
        ).first()
        if root is None:
            return
        open_snapshots = (
            (
                await self._session.execute(
                    select(Snapshot).where(
                        Snapshot.volume_id == volume_id, Snapshot.finished.is_(None)
                    )
                )
            )
            .scalars()
            .all()
        )
        now = datetime.now(tz=UTC)
        for snap in open_snapshots:
            snap.total_size = root.total_size_on_disk
            snap.file_count = root.file_count
            snap.finished = now

    async def _rebuild_dedup(self, host_id: int) -> int:
        """Rebuild the estate-wide report-only dup groups — gated on the finalizing HOST's hashes.

        The grouping itself is estate-wide (empty :class:`DedupScope`) so a duplicate spanning two
        volumes — or two hosts — surfaces, not just within the finalizing host. But the *trigger* is
        scoped to whether THIS host has any ``full_hash`` at all: a host that has never contributed
        a content hash (a metadata-only deployment, or a W1 Windows agent) cannot have changed any
        dup group, so in a MIXED estate — where OTHER hosts carry hashes — it must not trigger (or
        pay for) a full estate rebuild on its routine finalizes. Before this scope-down the gate was
        estate-wide, so a metadata-only agent's finalize rebuilt the entire estate's groups (e.g.
        ~140k), pinning the API worker and blowing the proxy request timeout (a spurious 504, and a
        real CPU spike on the catalogue host). Gating on the host — not on the *stale* volumes —
        keeps a full-bit host's re-finalize a faithful rebuild (idempotent) while a metadata host
        always skips. Runs in the caller's transaction so groups commit atomically with the rollups.
        """
        if not self._build_dedup:
            return 0
        has_hashes = (
            await self._session.execute(
                select(FsEntryRow.id)
                .join(Volume, Volume.id == FsEntryRow.volume_id)
                .where(Volume.host_id == host_id, FsEntryRow.full_hash.is_not(None))
                .limit(1)
            )
        ).first()
        if has_hashes is None:
            return 0
        # rebuild() (not build()) so the estate-scale finalize returns just the count without
        # holding every group object resident — collecting them OOM-killed the 1 GiB API worker.
        return await DedupService(self._session).rebuild(scope=DedupScope(), job_id="finalize")

    async def _stale_volume_ids(self, host_id: int) -> list[int]:
        """Return this host's volume ids whose latest snapshot post-dates their latest rollup.

        A volume is stale when it has a snapshot started at/after its most recent rollup's
        ``computed_at`` — or has snapshots but no rollup at all (the first-ever finalize). The
        comparison runs as two aggregate sub-selects keyed by ``volume_id`` so it stays bounded
        regardless of how many entries the volume holds (no per-entry scan here; the heavy work
        is delegated to :meth:`RollupService.recompute_full`, which streams).
        """
        last_snapshot = (
            select(
                Snapshot.volume_id.label("volume_id"),
                func.max(Snapshot.started).label("last_started"),
            )
            .group_by(Snapshot.volume_id)
            .subquery()
        )
        last_rollup = (
            select(
                SubtreeRollup.volume_id.label("volume_id"),
                func.max(SubtreeRollup.computed_at).label("last_computed"),
            )
            .group_by(SubtreeRollup.volume_id)
            .subquery()
        )
        stmt = (
            select(Volume.id)
            .join(last_snapshot, last_snapshot.c.volume_id == Volume.id)
            .outerjoin(last_rollup, last_rollup.c.volume_id == Volume.id)
            .where(
                Volume.host_id == host_id,
                (last_rollup.c.last_computed.is_(None))
                | (last_snapshot.c.last_started >= last_rollup.c.last_computed),
            )
            .order_by(Volume.id)
        )
        rows = await self._session.execute(stmt)
        return list(rows.scalars().all())
