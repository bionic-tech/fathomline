"""Metadata scan orchestrator (ADD 02 §Mode 1, §"non-impact contract").

Drives a ``StorageBackend`` walk, applies the adaptive supervisor between batches, and
stages entries to local SQLite. This is the read-only, lowest-risk surface and the first
thing built (build order step 1). It physically cannot write to the scanned filesystem —
it only ``stat``s and stages — which is the code-level half of read ≠ write.

A *first* scan of a target refuses to run without an acknowledgement of the impact
warning; the acknowledgement (operator, timestamp, target, mode) is persisted on the scan
run for the audit trail.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, Field

from fathom.agent.reader.supervisor import LoadSupervisor
from fathom.agent.staging.store import StagingStore
from fathom.backends.base import FsEntry, StorageBackend, VolumeInfo
from fathom.logging import get_logger

_log = get_logger("fathom.agent.walker")

DEFAULT_BATCH_SIZE = 1000


class AcknowledgementRequired(RuntimeError):
    """Raised when a first scan is attempted without acknowledging the impact warning."""


class WarningAck(BaseModel):
    """Operator acknowledgement of the first-scan impact warning (ADD 02)."""

    operator: str = Field(min_length=1)
    acknowledged_at: datetime
    target: str
    mode: str


@dataclass(slots=True)
class ScanResult:
    """Outcome of a metadata scan."""

    run_id: int
    volume: VolumeInfo
    entries_seen: int
    rows_changed: int


class MetadataScanner:
    """Orchestrates a throttled, metadata-only scan into the local staging store."""

    def __init__(
        self,
        *,
        backend: StorageBackend,
        staging: StagingStore,
        supervisor: LoadSupervisor,
        host_id: str,
        batch_size: int = DEFAULT_BATCH_SIZE,
        one_filesystem: bool = True,
        exclude: Collection[str] = (),
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        self._backend = backend
        self._staging = staging
        self._supervisor = supervisor
        self._host_id = host_id
        self._batch_size = batch_size
        # Off → descend into nested mounts (ZFS child datasets under a pool root).
        self._one_filesystem = one_filesystem
        # ADR-034: absolute directory prefixes the walk prunes (never reports/descends).
        self._exclude = tuple(exclude)

    async def scan(
        self,
        root: str,
        *,
        warning_ack: WarningAck | None = None,
    ) -> ScanResult:
        """Scan ``root`` (metadata only), staging deltas. Requires ``warning_ack``.

        Args:
            root: The directory to scan; must be supported by the backend.
            warning_ack: The operator's acknowledgement of the impact warning. Required —
                a metadata scan never starts unacknowledged (the non-impact contract).

        Returns:
            A :class:`ScanResult` with the run id, resolved volume, entries seen, and the
            number of new-or-changed rows staged.

        Raises:
            AcknowledgementRequired: If ``warning_ack`` is missing.
        """
        if warning_ack is None:
            raise AcknowledgementRequired(
                f"first scan of {root!r} requires an acknowledged impact warning (ADD 02)"
            )

        volume = await self._backend.volume_info(root)
        volume_id = volume.mountpoint
        run_id = await asyncio.to_thread(
            self._staging.start_run,
            host_id=self._host_id,
            volume_id=volume_id,
            mode="metadata",
            root=root,
            started_at=time.time(),
            warning_ack=warning_ack.model_dump(mode="json"),
            volume=volume.model_dump(mode="json"),
        )
        _log.info(
            "metadata scan started",
            extra={"root": root, "volume": volume_id, "run_id": run_id, "host_id": self._host_id},
        )

        seen = 0
        changed = 0
        batch: list[FsEntry] = []
        async for entry in self._backend.walk(
            root, one_filesystem=self._one_filesystem, exclude=self._exclude
        ):
            batch.append(entry)
            seen += 1
            if len(batch) >= self._batch_size:
                await self._supervisor.wait_if_paused()
                changed += await self._flush(run_id, volume_id, batch)
                batch = []
        if batch:
            changed += await self._flush(run_id, volume_id, batch)

        await asyncio.to_thread(
            self._staging.finish_run, run_id, finished_at=time.time(), entry_count=seen
        )
        _log.info(
            "metadata scan finished",
            extra={"run_id": run_id, "entries_seen": seen, "rows_changed": changed},
        )
        return ScanResult(run_id=run_id, volume=volume, entries_seen=seen, rows_changed=changed)

    async def _flush(self, run_id: int, volume_id: str, batch: list[FsEntry]) -> int:
        return await asyncio.to_thread(
            self._staging.stage_batch,
            run_id=run_id,
            host_id=self._host_id,
            volume_id=volume_id,
            entries=batch,
        )
