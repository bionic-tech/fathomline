"""Subtree rollups — instant drill-down totals (ADD 09 §8).

This module computes the full baseline rollup (the one-time bottom-up pass that is part of
the warned initial scan). Each entry contributes its size and a unit count to every ancestor
directory down to the volume mountpoint, so a directory's rollup is the total of everything
beneath it. Subsequent incremental recompute of only the affected ancestor paths (driven by
the change feed) is a later optimisation; this baseline pass is correct and portable.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.catalogue.models import FsEntryRow, SizeHistory, SubtreeRollup, Volume

# At estate scale a single volume holds millions of entries that roll up into ~hundreds of
# thousands of directory rows. Inserting those via the ORM unit-of-work would materialise one
# mapped object (plus identity-map/flush state) per row — ~600 MB for 636k rows — which OOMs the
# 1 GiB api worker the finalize runs inside. Rows are streamed to the DB in Core bulk-insert
# batches of this size instead, so peak memory stays bounded by the tally, not the row count.
_ROLLUP_INSERT_CHUNK = 5000
# Bound the server-side read cursor's client buffer so the 3.15M-row streaming scan never
# materialises the whole result set at once.
_ENTRY_STREAM_YIELD = 10000


@dataclass(slots=True)
class _Acc:
    total_size_logical: int = 0
    total_size_on_disk: int = 0
    file_count: int = 0
    dir_count: int = 0


@dataclass(slots=True)
class _Tally:
    by_path: dict[str, _Acc] = field(default_factory=lambda: defaultdict(_Acc))


def _ancestor_dirs(path: str, mount: str) -> list[str]:
    """Ancestor directory paths of ``path`` from ``mount`` down to its immediate parent."""
    if path == mount or not path.startswith(mount.rstrip("/") + "/"):
        return [] if path == mount else [mount]
    rel = path[len(mount) :].strip("/")
    parts = rel.split("/")
    out = [mount]
    cur = mount.rstrip("/")
    for part in parts[:-1]:
        cur = f"{cur}/{part}"
        out.append(cur)
    return out


def _depth_within(mount: str, path: str) -> int:
    rel = path[len(mount) :].strip("/")
    return 0 if not rel else rel.count("/") + 1


def _batched(rows: Iterator[dict[str, object]], size: int) -> Iterator[list[dict[str, object]]]:
    """Group a lazy row stream into lists of at most ``size`` (no full materialisation)."""
    batch: list[dict[str, object]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


class RollupService:
    """Recomputes ``subtree_rollup`` (and appends a ``size_history`` point) for a volume."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def recompute_full(self, volume_id: int) -> int:
        """Rebuild the full rollup for ``volume_id``. Returns the number of rollup rows."""
        volume = await self._session.get(Volume, volume_id)
        if volume is None:
            raise ValueError(f"unknown volume_id {volume_id}")
        mount = volume.mountpoint

        tally = _Tally()
        # Stream the *raw columns* — not the ORM entity. A full ``select(FsEntryRow)`` adds every
        # row to the session identity map even under ``stream_scalars``, so at estate scale
        # (3.15M rows on one volume) memory grows unbounded and the recompute OOMs. Selecting the
        # four scalar columns yields lightweight ``Row`` tuples the identity map never tracks, so
        # peak memory is bounded by the rollup tally (one ``_Acc`` per *directory*, ~600k), not by
        # the entry count. Only live (``present``) entries contribute, so a re-finalize after an
        # incremental pass never lets a soft-deleted entry inflate a current subtree total.
        result = await self._session.stream(
            select(
                FsEntryRow.path,
                FsEntryRow.size_logical,
                FsEntryRow.size_on_disk,
                FsEntryRow.is_dir,
            )
            .where(FsEntryRow.volume_id == volume_id, FsEntryRow.present.is_(True))
            .execution_options(yield_per=_ENTRY_STREAM_YIELD)
        )
        async for path, size_logical, size_on_disk, is_dir in result:
            for ancestor in _ancestor_dirs(path, mount):
                acc = tally.by_path[ancestor]
                acc.total_size_logical += size_logical
                acc.total_size_on_disk += size_on_disk
                if is_dir:
                    acc.dir_count += 1
                else:
                    acc.file_count += 1

        # Replace the volume's rollup atomically within the caller's transaction.
        await self._session.execute(
            delete(SubtreeRollup).where(SubtreeRollup.volume_id == volume_id)
        )
        now = datetime.now(tz=UTC)
        # Bulk-insert the rollup rows via Core in bounded batches. The ORM unit-of-work path
        # (``session.add`` per row) would hold one mapped object + flush state per directory —
        # ~600 MB for 636k rows — and OOM the 1 GiB worker. Core ``insert()`` with plain dict
        # batches carries no identity-map/instance-state overhead, so peak stays bounded by the
        # tally itself.
        inserted = 0
        rows = self._rollup_rows(volume_id, mount, tally, now)
        for batch in _batched(rows, _ROLLUP_INSERT_CHUNK):
            await self._session.execute(insert(SubtreeRollup), batch)
            inserted += len(batch)

        root = tally.by_path.get(mount, _Acc())
        self._session.add(
            SizeHistory(
                volume_id=volume_id,
                path=mount,
                ts=now,
                total_size_logical=root.total_size_logical,
                total_size_on_disk=root.total_size_on_disk,
                file_count=root.file_count,
            )
        )
        await self._session.flush()
        return inserted

    @staticmethod
    def _rollup_rows(
        volume_id: int, mount: str, tally: _Tally, now: datetime
    ) -> Iterator[dict[str, object]]:
        """Yield one Core-insert mapping per accumulated directory (lazy, no full list held)."""
        for path, acc in tally.by_path.items():
            yield {
                "volume_id": volume_id,
                "path": path,
                "depth": _depth_within(mount, path),
                "total_size_logical": acc.total_size_logical,
                "total_size_on_disk": acc.total_size_on_disk,
                "file_count": acc.file_count,
                "dir_count": acc.dir_count,
                "computed_at": now,
            }
