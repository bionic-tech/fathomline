"""Full-bit scan orchestrator (ADD 02 §Mode 2, fullbit-dedup spec).

The content-hashing sibling of :class:`~fathom.agent.reader.walker.MetadataScanner`. For an
operator-specified scope it runs the documented *progressive funnel* — size bucket within the
scope's already-staged candidates → 4 KiB head+tail partial BLAKE3 → full BLAKE3 — using the
already-built :class:`~fathom.agent.reader.hasher.BackendHasher` over the owning host's backend
(``open_for_hash`` uses ``O_NOFOLLOW``, so a symlink is never traversed for content). Only the
content hashes are staged, keyed to the same ``(host, volume, inode)`` identity as the metadata
row; raw bytes never leave the host (ADR-002).

Full-bit is hard-gated, in order:

1. It refuses to start without a :class:`WarningAck` whose ``mode == 'fullbit'`` and whose
   message names the backing device class (the non-impact contract; security_constraints).
2. It refuses to start while the backing array is resyncing/resilvering — the
   :meth:`LoadSupervisor.should_block_fullbit_async` guard (ADD 02 hard rule, AR-0002 §5).
3. Between hash batches it awaits :meth:`LoadSupervisor.wait_if_paused`, so a rising host load
   pauses hashing exactly like a metadata walk (ADD 02 state diagram).

This module only ever *reads* bytes and stages hashes — it has no write capability (read ≠
write). It is strictly the producer side of the report-only dedup pipeline.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal

from fathom.agent.reader.hasher import BackendHasher
from fathom.agent.reader.supervisor import LoadSupervisor
from fathom.agent.reader.walker import AcknowledgementRequired, WarningAck
from fathom.agent.staging.store import StagingStore
from fathom.backends.base import StorageBackend, VolumeInfo
from fathom.core.dedup import Candidate
from fathom.logging import get_logger

_log = get_logger("fathom.agent.fullbit")

FULLBIT_MODE: Final[Literal["fullbit"]] = "fullbit"
DEFAULT_HASH_BATCH = 64


class FullBitBlocked(RuntimeError):
    """Raised when a full-bit scan is refused because an array is resyncing/resilvering.

    This is the hard rule from the non-impact contract (ADD 02 ``hard_rules``): a full-bit scan
    must never compete with a RAID rebuild / ZFS resilver for I/O. It is a refusal, never a
    silent skip (ADD 16).
    """


@dataclass(slots=True)
class FullBitResult:
    """Outcome of a full-bit scan over one scope."""

    run_id: int
    scope_root: str
    candidates: int
    partial_hashed: int
    full_hashed: int
    staged: int
    # The (host_id, volume_id, inode) identities that were content-hashed, for assertion/audit.
    hashed_keys: list[tuple[str, str, int]] = field(default_factory=list)


class FullBitScanner:
    """Runs the ack-gated, resync-blocked, throttled progressive funnel into staging."""

    def __init__(
        self,
        *,
        backend: StorageBackend,
        hasher: BackendHasher,
        staging: StagingStore,
        supervisor: LoadSupervisor,
        host_id: str,
        hash_concurrency: int = 2,
    ) -> None:
        if hash_concurrency < 1:
            raise ValueError("hash_concurrency must be >= 1")
        self._backend = backend
        self._hasher = hasher
        self._staging = staging
        self._supervisor = supervisor
        self._host_id = host_id
        self._hash_concurrency = hash_concurrency

    async def scan(
        self,
        scope_root: str,
        candidates: Iterable[Candidate],
        *,
        volume_id: str,
        warning_ack: WarningAck | None = None,
        volume: VolumeInfo | None = None,
    ) -> FullBitResult:
        """Hash the dedup-relevant subset of an in-memory ``candidates`` iterable.

        Groups ``candidates`` by size and delegates to :meth:`scan_grouped`. This is the
        bounded-input path (tests, small scopes); production scans use :meth:`scan_grouped`
        directly with a size-bucketed stream from the staging store, so they never materialise the
        whole candidate set — the materialisation that OOM-killed the scanner on million-file hosts
        (ADR-025 scan-fix).

        Args:
            scope_root: The full-bit scope root (within the agent's fullbit allow-list).
            candidates: Files to consider (``id`` is the entry inode; ``path`` and ``size``
                drive the funnel). Zero-byte files are skipped (nothing reclaimable).
            volume_id: The staging volume id (mountpoint) the hashes are keyed under.
            warning_ack: The operator's full-bit impact acknowledgement. Required, and its
                ``mode`` must be ``'fullbit'`` — a metadata ack does not authorise a content read.

        Returns:
            A :class:`FullBitResult` summarising candidates seen and hashes staged.

        Raises:
            AcknowledgementRequired: If ``warning_ack`` is missing or not a full-bit ack.
            FullBitBlocked: If the supervisor blocks full-bit (array resyncing/resilvering).
        """
        by_size: dict[int, list[Candidate]] = defaultdict(list)
        for cand in candidates:
            if cand.size > 0:
                by_size[cand.size].append(cand)

        async def _groups() -> AsyncIterator[Sequence[Candidate]]:
            for sized in by_size.values():
                yield sized

        return await self.scan_grouped(
            scope_root, _groups(), volume_id=volume_id, warning_ack=warning_ack, volume=volume
        )

    async def scan_grouped(
        self,
        scope_root: str,
        groups: AsyncIterator[Sequence[Candidate]],
        *,
        volume_id: str,
        warning_ack: WarningAck | None = None,
        volume: VolumeInfo | None = None,
    ) -> FullBitResult:
        """Run the progressive funnel one size-group at a time from a streamed ``groups`` source.

        Each item of ``groups`` is one size-bucket of candidates (all the same size), yielded
        independently, so peak memory is a single group rather than the whole scope (ADR-025
        scan-fix). The gates (ack, resync-block) are checked once up front, before any group is
        pulled or the run row is created.

        Raises:
            AcknowledgementRequired: If ``warning_ack`` is missing or not a full-bit ack.
            FullBitBlocked: If the supervisor blocks full-bit (array resyncing/resilvering).
        """
        if warning_ack is None or warning_ack.mode != FULLBIT_MODE:
            raise AcknowledgementRequired(
                f"full-bit scan of {scope_root!r} requires a WarningAck(mode='fullbit') naming "
                "the backing device class (ADD 02 non-impact contract)"
            )
        if await self._supervisor.should_block_fullbit_async():
            raise FullBitBlocked(
                f"full-bit scan of {scope_root!r} blocked: backing array is resyncing/resilvering "
                "(ADD 02 hard rule)"
            )

        run_id = await asyncio.to_thread(
            self._staging.start_run,
            host_id=self._host_id,
            volume_id=volume_id,
            mode=FULLBIT_MODE,
            root=scope_root,
            started_at=time.time(),
            warning_ack=warning_ack.model_dump(mode="json"),
            # Persist the VolumeInfo on the full-bit run too: without it the run's volume_json is
            # NULL and the drain sends a zero/empty volume frame that clobbers the catalogue's real
            # capacity/fs_type/topology for this volume (the metadata run captured it; full-bit must
            # not erase it).
            volume=volume.model_dump(mode="json") if volume is not None else None,
        )
        _log.info(
            "full-bit scan started",
            extra={"scope": scope_root, "volume": volume_id, "run_id": run_id},
        )

        result = FullBitResult(
            run_id=run_id,
            scope_root=scope_root,
            candidates=0,
            partial_hashed=0,
            full_hashed=0,
            staged=0,
        )
        async for group in groups:
            result.candidates += len(group)
            await self._funnel_group(group, volume_id=volume_id, run_id=run_id, result=result)

        await asyncio.to_thread(
            self._staging.finish_run, run_id, finished_at=time.time(), entry_count=result.staged
        )
        _log.info(
            "full-bit scan finished",
            extra={
                "run_id": run_id,
                "candidates": result.candidates,
                "full_hashed": result.full_hashed,
                "staged": result.staged,
            },
        )
        return result

    async def _funnel_group(
        self,
        sized: Sequence[Candidate],
        *,
        volume_id: str,
        run_id: int,
        result: FullBitResult,
    ) -> None:
        """Run partial → full over ONE same-size group, staging only size+partial colliders.

        A unique size never reaches here (the caller's size source filters it); a file whose
        head/tail partial is unique within the group is never fully hashed (progressive funnel
        correctness — fullbit-dedup test_plan). Memory is bounded by this single group.
        """
        if len(sized) < 2:
            return  # unique size → never opened
        size = sized[0].size
        # by_partial maps each partial digest to its colliding candidates (within this size group).
        by_partial: dict[str, list[Candidate]] = defaultdict(list)
        for batch in _chunked(sized, DEFAULT_HASH_BATCH):
            await self._supervisor.wait_if_paused()
            partials = await self._hash_batch([(c.path, size) for c in batch], full=False)
            for cand, digest in zip(batch, partials, strict=True):
                if digest is None:
                    continue  # file vanished/unreadable this pass — skipped, not fatal
                by_partial[digest].append(cand)
                result.partial_hashed += 1

        for partial_digest, partial_members in by_partial.items():
            if len(partial_members) < 2:
                continue  # unique partial → never fully hashed
            for batch in _chunked(partial_members, DEFAULT_HASH_BATCH):
                await self._supervisor.wait_if_paused()
                fulls = await self._hash_batch([(c.path, size) for c in batch], full=True)
                for cand, full_digest in zip(batch, fulls, strict=True):
                    if full_digest is None:
                        continue  # file vanished/unreadable this pass — skipped, not fatal
                    result.full_hashed += 1
                    await self._stage(
                        cand,
                        volume_id=volume_id,
                        run_id=run_id,
                        partial_hash=partial_digest,
                        full_hash=full_digest,
                        result=result,
                    )

    async def _hash_batch(self, items: list[tuple[str, int]], *, full: bool) -> list[str | None]:
        """Hash ``(path, size)`` items concurrently, bounded by ``hash_concurrency``.

        A file staged during the metadata walk can vanish or lose read access before this later
        pass (TOCTOU on a live filesystem). That one file yields ``None`` (skipped + logged), never
        an exception that aborts the whole batch — one transient file must not kill content-hashing
        for the entire scope. The metadata walk is already resilient the same way.
        """
        sem = asyncio.Semaphore(self._hash_concurrency)

        async def _one(path: str, size: int) -> str | None:
            async with sem:
                try:
                    if full:
                        return await self._hasher.full(path)
                    return await self._hasher.partial(path, size)
                except OSError as exc:
                    _log.warning(
                        "full-bit hash skipped (file vanished/unreadable)",
                        extra={"path": path, "error": str(exc)},
                    )
                    return None

        coros: list[Awaitable[str | None]] = [_one(path, size) for path, size in items]
        return list(await asyncio.gather(*coros))

    async def _stage(
        self,
        cand: Candidate,
        *,
        volume_id: str,
        run_id: int,
        partial_hash: str,
        full_hash: str,
        result: FullBitResult,
    ) -> None:
        inode = int(cand.id)
        await asyncio.to_thread(
            self._staging.stage_hash,
            host_id=self._host_id,
            volume_id=volume_id,
            inode=inode,
            partial_hash=partial_hash,
            full_hash=full_hash,
            scan_run_id=run_id,
            # dev (st_dev) matches the staged metadata row's (host, volume, dev, inode) identity:
            # without it a cross-dataset full-bit hash would update the wrong row or none at all.
            dev=cand.dev,
        )
        result.staged += 1
        result.hashed_keys.append((self._host_id, volume_id, inode))


def _chunked(seq: Sequence[Candidate], size: int) -> Iterable[list[Candidate]]:
    for i in range(0, len(seq), size):
        yield list(seq[i : i + size])
