"""Incremental scanner — stage a change-feed delta instead of a full walk (ADR-006, ADD 02 §incr).

After the warned first index, the agent runs the light-touch change feed (``zfs diff`` /
re-``stat``) instead of re-walking 50M files. This scanner drives a :class:`ChangeFeed` for one
``root``, reconciles its events into the minimal delta (:func:`collect_delta`), and stages both
the created/modified entries (idempotent upserts, like a walk) and the **explicit removed inodes**
(``staged_removal``) for the push client to drain. It is metadata-only and throttle-aware, exactly
like the full :class:`~fathom.agent.reader.walker.MetadataScanner`, and reuses the same staging
store and supervisor — so the non-impact contract holds on an incremental cycle too.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from fathom.agent.reader.feed import ChangeFeed, collect_delta
from fathom.agent.reader.supervisor import LoadSupervisor
from fathom.agent.reader.walker import WarningAck
from fathom.agent.staging.store import StagingStore
from fathom.backends.base import StorageBackend
from fathom.logging import get_logger

_log = get_logger("fathom.agent.incremental")


@dataclass(slots=True)
class IncrementalResult:
    """Outcome of one incremental change-feed cycle."""

    run_id: int
    upserts_staged: int
    removals_staged: int

    @property
    def is_empty(self) -> bool:
        return self.upserts_staged == 0 and self.removals_staged == 0


class IncrementalScanner:
    """Drives a :class:`ChangeFeed` into staging (upserts + explicit removals), throttle-aware."""

    def __init__(
        self,
        *,
        backend: StorageBackend,
        staging: StagingStore,
        supervisor: LoadSupervisor,
        host_id: str,
    ) -> None:
        self._backend = backend
        self._staging = staging
        self._supervisor = supervisor
        self._host_id = host_id

    async def scan(
        self,
        root: str,
        feed: ChangeFeed,
        *,
        warning_ack: WarningAck,
    ) -> IncrementalResult:
        """Collect ``feed``'s delta under ``root`` and stage upserts + removals.

        The feed is metadata-only (no content reads) and never widens scope beyond ``root`` — the
        server re-enforces the volume boundary regardless (AR-0012). Pauses before staging if the
        supervisor reports the host over its load ceiling, so an incremental cycle is as
        non-impacting as the full scan.
        """
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
        await self._supervisor.wait_if_paused()
        delta = await collect_delta(feed, root)

        upserts = 0
        if delta.upserts:
            upserts = await asyncio.to_thread(
                self._staging.stage_batch,
                run_id=run_id,
                host_id=self._host_id,
                volume_id=volume_id,
                entries=delta.upserts,
            )
        removals = 0
        if delta.removals:
            # The feed carries the (dev, inode, path) of each removal so the staged removal — and
            # the server's DELETE churn row — records a real path and flips only the right device.
            removals = await asyncio.to_thread(
                self._staging.stage_removals,
                run_id=run_id,
                host_id=self._host_id,
                volume_id=volume_id,
                removals=delta.removals,
            )

        await asyncio.to_thread(
            self._staging.finish_run,
            run_id,
            finished_at=time.time(),
            entry_count=len(delta.upserts),
        )
        _log.info(
            "incremental cycle staged",
            extra={
                "root": root,
                "run_id": run_id,
                "upserts": upserts,
                "removals": removals,
            },
        )
        return IncrementalResult(run_id=run_id, upserts_staged=upserts, removals_staged=removals)
