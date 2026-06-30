"""mTLS agent-push client and the resumable staging drain (ADR-002, ADD 02 §7).

``mtls_client`` builds an httpx client that presents the agent's client certificate and
**pins the Fathom CA** as the only trust anchor (``verify=<ca>``) — a public CA cannot
satisfy it, defeating MITM (AR-0010). ``PushClient.drain`` walks the local staging queue
run-by-run, pushes bounded idempotent batches, and only marks rows pushed after the server
acknowledges — so a crash mid-drain re-pushes harmlessly (the server upsert is idempotent).
Failed pushes retry with exponential backoff and jitter (AR-0024).
"""

from __future__ import annotations

import asyncio
import json
import random
import sqlite3
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

from fathom.agent import host_facts
from fathom.agent.config import AgentConfig
from fathom.agent.staging.store import StagingStore
from fathom.api.schemas import (
    EntryFrame,
    HostFactsFrame,
    HostFrame,
    IngestBatch,
    IngestResult,
    VolumeFrame,
)
from fathom.logging import get_logger

_log = get_logger("fathom.agent.transport")

DEFAULT_PUSH_CHUNK = 1000


def mtls_client(config: AgentConfig, *, timeout: float = 30.0) -> httpx.AsyncClient:
    """Build a CA-pinned mTLS httpx client for ``config`` (AR-0010).

    Builds an explicit ``SSLContext`` rather than using httpx's ``cert=``/``verify=``
    shortcuts: passing ``cafile`` makes the Fathom CA the *only* trust anchor (no public-CA
    fallback — server-cert pinning), and ``load_cert_chain`` presents the agent's client
    certificate for mTLS. This is also the form that reliably sends the client cert across
    httpx versions.
    """
    ssl_ctx = ssl.create_default_context(cafile=config.server_ca_path)
    ssl_ctx.load_cert_chain(certfile=config.client_cert_path, keyfile=config.client_key_path)
    return httpx.AsyncClient(
        base_url=config.ingest_url.rsplit("/api/", 1)[0] or config.ingest_url,
        verify=ssl_ctx,
        timeout=timeout,
    )


@dataclass(slots=True)
class RetryPolicy:
    """Exponential backoff with jitter for transient push failures (AR-0024)."""

    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 30.0

    def delay_for(self, attempt: int) -> float:
        """Return the (jittered) delay before ``attempt`` (1-based)."""
        raw: float = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
        jitter: float = 0.5 + random.random() / 2  # noqa: S311 — jitter, not crypto
        return float(raw * jitter)


def _row_to_entry(r: sqlite3.Row) -> EntryFrame:
    # Hashes are present only on rows staged by a full-bit run; a metadata-only row leaves them
    # None and the server then leaves the catalogue columns untouched (fullbit-dedup).
    keys = r.keys()
    return EntryFrame(
        path=r["path"],
        name=r["name"],
        is_dir=bool(r["is_dir"]),
        is_symlink=bool(r["is_symlink"]),
        size_logical=r["size_logical"],
        size_on_disk=r["size_on_disk"],
        mtime=r["mtime"],
        ctime=r["ctime"],
        uid=r["uid"],
        gid=r["gid"],
        inode=r["inode"],
        # dev (st_dev) is part of the entry identity; read it defensively (default 0) so a row
        # staged before the column existed still maps, mirroring the partial_hash/full_hash guard.
        dev=r["dev"] if "dev" in keys else 0,
        flags=json.loads(r["flags"]) if r["flags"] else {},
        partial_hash=r["partial_hash"] if "partial_hash" in keys else None,
        full_hash=r["full_hash"] if "full_hash" in keys else None,
    )


class PushClient:
    """Pushes staged deltas to the core ingest endpoint over an injected httpx client."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        ingest_path: str = "/api/v1/agents/ingest",
        retry: RetryPolicy | None = None,
        chunk_size: int = DEFAULT_PUSH_CHUNK,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._client = client
        self._ingest_path = ingest_path
        self._retry = retry or RetryPolicy()
        self._chunk_size = chunk_size
        self._sleep = sleeper

    async def push(self, batch: IngestBatch) -> IngestResult:
        """POST one batch, retrying transient failures with backoff+jitter."""
        last_exc: Exception | None = None
        for attempt in range(1, self._retry.max_attempts + 1):
            try:
                resp = await self._client.post(
                    self._ingest_path, json=batch.model_dump(mode="json")
                )
                resp.raise_for_status()
                return IngestResult.model_validate(resp.json())
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                last_exc = exc
                if attempt >= self._retry.max_attempts:
                    break
                delay = self._retry.delay_for(attempt)
                _log.warning(
                    "push failed; backing off",
                    extra={"attempt": attempt, "delay": round(delay, 2), "error": str(exc)},
                )
                await self._sleep(delay)
        raise PushError(f"push failed after {self._retry.max_attempts} attempts") from last_exc

    async def drain(self, staging: StagingStore) -> int:
        """Push every unpushed staged row + removal, marking pushed only after acknowledgement.

        Returns the total number of entries pushed (removals are counted separately on the server).
        Idempotent and resumable: a crash mid-drain re-pushes harmlessly because both the upsert
        and the removal (present=false flip) are idempotent on the server.
        """
        total = 0
        # Probe this host's hardware once for the whole drain (ADR-037) — it does not change between
        # runs. Best-effort + off the event loop (nvidia-smi may block); a failure leaves facts None
        # so the drain proceeds exactly as before.
        facts = await self._probe_facts()
        for run in staging.pending_runs():
            host = HostFrame(name=run["host_id"], facts=facts)
            volume = self._volume_frame(run)
            snapshot_id: int | None = None
            while True:
                rows = staging.unpushed_for_run(run["id"], limit=self._chunk_size)
                if not rows:
                    break
                batch = IngestBatch(
                    host=host,
                    volume=volume,
                    mode=run["mode"],
                    snapshot_id=snapshot_id,
                    entries=[_row_to_entry(r) for r in rows],
                )
                result = await self.push(batch)
                snapshot_id = result.snapshot_id  # keep all chunks in one snapshot
                staging.mark_pushed(
                    [(r["host_id"], r["volume_id"], r["dev"], r["inode"]) for r in rows]
                )
                total += len(rows)
            # Drain this run's removals (the incremental change feed's explicit deletions). They
            # ride in their own bounded chunks carrying no entries — the server marks each removed
            # inode present=false and emits a DELETE churn row (incremental subsystem).
            await self._drain_removals(staging, run, snapshot_id)
        return total

    async def _probe_facts(self) -> HostFactsFrame | None:
        """Probe host hardware off the event loop; return None on any failure (fail-soft)."""
        try:
            raw = await asyncio.to_thread(host_facts.collect)
            return HostFactsFrame(**raw)
        except Exception as exc:  # a facts probe must never break a drain
            _log.warning(
                "host-facts probe failed; reporting without facts", extra={"error": str(exc)}
            )
            return None

    async def _drain_removals(
        self, staging: StagingStore, run: sqlite3.Row, snapshot_id: int | None
    ) -> None:
        """Push the run's staged removals in bounded chunks, marking each pushed on ack."""
        host = HostFrame(name=run["host_id"])
        volume = self._volume_frame(run)
        while True:
            rows = staging.unpushed_removals_for_run(run["id"], limit=self._chunk_size)
            if not rows:
                break
            batch = IngestBatch(
                host=host,
                volume=volume,
                # Removals are a metadata-mode signal regardless of the run's scan mode: a full-bit
                # run never detects deletions, so a removal batch is always metadata reconciliation.
                mode="metadata",
                snapshot_id=snapshot_id,
                entries=[],
                # Precise (dev, inode) removals (matches the catalogue identity so a cross-dataset
                # inode collision flips only the right device's row). ``removed_inodes`` is sent too
                # so an older server that predates the ``removed`` field still applies the removal.
                removed=[{"dev": r["dev"], "inode": r["inode"]} for r in rows],
                removed_inodes=[r["inode"] for r in rows],
            )
            await self.push(batch)
            staging.mark_removals_pushed(
                [(r["host_id"], r["volume_id"], r["dev"], r["inode"]) for r in rows]
            )

    @staticmethod
    def _volume_frame(run: sqlite3.Row) -> VolumeFrame:
        raw = run["volume_json"]
        if raw:
            data = json.loads(raw)
            return VolumeFrame(
                mountpoint=data["mountpoint"],
                display_name=data.get("display_name"),
                fs_type=data.get("fs_type", "unknown"),
                device=data.get("device", "unknown"),
                transport=data.get("transport", "unknown"),
                raid_role=data.get("raid_role"),
                pool=data.get("pool"),
                dataset=data.get("dataset"),
                total=data.get("total", 0),
                used=data.get("used", 0),
                free=data.get("free", 0),
            )
        # Fallback when a run predates volume capture: identify by mountpoint only.
        return VolumeFrame(
            mountpoint=run["volume_id"],
            fs_type="unknown",
            device="unknown",
            transport="unknown",
            total=0,
            used=0,
            free=0,
        )


class PushError(RuntimeError):
    """Raised when a batch could not be pushed within the retry budget."""
