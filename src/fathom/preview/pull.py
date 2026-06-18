"""Distributed preview file pull — the core side of the signed single-file pull (ADR-014).

A single-host deployment reads the file off local disk (:class:`~fathom.preview.local_fetch.
LocalFileFetcher`). A DISTRIBUTED deployment cannot: the bytes live on the agent host and the
preview worker has **no broad data mount** (owner ruling). So the core mints a signed, nonce'd,
short-TTL :class:`~fathom.preview.grant.FileGrant` for exactly one file and hands it to that
file's owning agent over the agent-**initiated** channel (no new inbound agent port):

* :class:`GrantPullFetcher` is the :class:`~fathom.preview.service.FileFetcher` the worker's
  ``PreviewService`` injects. From the service's point of view it is just "give me this file's
  bytes"; the grant dance is hidden here.
* :class:`PreviewPullQueue` is the per-host rendezvous (mirrors the remediation
  :class:`~fathom.core.remediation.job_queue.JobQueue`): the fetcher ``enqueue_and_wait``s a
  signed grant; the owning agent long-polls ``poll`` for it, verifies it fail-closed
  (:func:`~fathom.preview.grant.verify_grant`), reads exactly that one file, and ``deliver``s the
  bytes back, which resolves the awaiting fetch.

Security (this reintroduces a read of agent-side file content — ADR-014 review surface): every
grant is Ed25519-signed, single-use (nonce ledger, agent side), host-scoped, and TTL-bounded. The
queue refuses a result from any host other than the one the grant was issued to
(:class:`PullCorrelationError`), so a rogue agent cannot answer for another host. The dispatch
window equals the grant TTL, so a fetch that times out has also expired — nothing serves bytes
after the fetch gave up.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fathom.logging import get_logger
from fathom.preview.grant import FileGrant, GrantSigner, SignedFileGrant
from fathom.preview.service import ResolvedEntry
from fathom.preview.types import PreviewError

_log = get_logger("fathom.preview.pull")

DEFAULT_POLL_TIMEOUT_SECONDS = 25.0


class PreviewPullError(RuntimeError):
    """The owning agent did not serve the file within the grant window (fail-closed → 504)."""


class PullCorrelationError(RuntimeError):
    """A served result could not be matched to an awaiting pull (spoofed / cross-host / replayed).

    Raised when a delivery names a ``grant_id`` that was never issued, was already resolved, or is
    posted by a host other than the one the grant was scoped to. The route maps it to a 409 without
    disclosing which case it was (no cross-host disclosure).
    """


# What the agent's poll returns: the signed grant plus the authoritative server-side byte cap the
# agent must not exceed when reading the file (the core re-checks the returned length too).
PolledGrant = tuple[SignedFileGrant, int]

# Absolute parse-time ceiling on the base64 serve body (DoS backstop): a single authenticated agent
# must not be able to post an unbounded blob and OOM the core before the per-request cap is applied.
# 512 MiB of base64 ≈ 384 MiB raw — comfortably above the 256 MiB default preview_max_input_bytes;
# the serve route additionally enforces the *configured* cap precisely (and the mTLS proxy caps the
# body too). Rejected by Pydantic before the body is ever decoded into memory.
MAX_SERVE_DATA_B64_CHARS = 512 * 1024 * 1024


class ClaimedGrant(BaseModel):
    """What the agent's poll route returns: the signed grant + the byte cap to read up to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signed_grant: SignedFileGrant
    max_bytes: int = Field(ge=1)


class ServeRequest(BaseModel):
    """The agent's reply for one grant: the file bytes (base64), or an ``error`` it could not serve.

    Exactly one of ``data_b64`` / ``error`` is set — a malformed reply that carries both or neither
    is rejected at the boundary (``extra='forbid'`` + the validator) so it can never half-resolve a
    pull.
    """

    model_config = ConfigDict(extra="forbid")

    grant_id: str = Field(min_length=1, max_length=64)
    data_b64: str | None = Field(default=None, max_length=MAX_SERVE_DATA_B64_CHARS)
    error: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def _exactly_one(self) -> ServeRequest:
        if (self.data_b64 is None) == (self.error is None):
            raise ValueError("exactly one of data_b64 / error must be set")
        return self


class PreviewPullQueue:
    """Per-host signed-grant rendezvous with awaited byte-result correlation (core side)."""

    def __init__(
        self,
        *,
        poll_timeout_seconds: float = DEFAULT_POLL_TIMEOUT_SECONDS,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        # One unbounded queue per host id; ``setdefault`` lazily creates it so an unknown host just
        # long-polls an empty queue (→ 204). Results are futures keyed by the grant id.
        self._queues: dict[str, asyncio.Queue[PolledGrant]] = {}
        self._results: dict[str, asyncio.Future[bytes]] = {}
        self._grant_host: dict[str, str] = {}
        self._poll_timeout = poll_timeout_seconds
        self._now = now or (lambda: datetime.now(tz=UTC))

    def _queue_for(self, host_id: str) -> asyncio.Queue[PolledGrant]:
        return self._queues.setdefault(host_id, asyncio.Queue())

    async def enqueue_and_wait(
        self, signed: SignedFileGrant, *, host_id: str, max_bytes: int, timeout_seconds: float
    ) -> bytes:
        """Enqueue ``signed`` for ``host_id`` and block on the agent's correlated byte result.

        Raises :class:`PreviewPullError` if no agent delivers within ``timeout_seconds`` (which the
        caller sets to the grant TTL, so a timed-out grant is also expired).
        """
        grant_id = signed.grant.grant_id
        if grant_id in self._results:
            raise PullCorrelationError("duplicate grant_id already in flight")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        self._results[grant_id] = future
        self._grant_host[grant_id] = host_id
        self._queue_for(host_id).put_nowait((signed, max_bytes))
        try:
            return await asyncio.wait_for(future, timeout=timeout_seconds)
        except TimeoutError as exc:
            raise PreviewPullError("preview file pull timed out") from exc
        finally:
            self._results.pop(grant_id, None)
            self._grant_host.pop(grant_id, None)

    def _expired(self, signed: SignedFileGrant) -> bool:
        expires = signed.grant.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return expires <= self._now()

    def _expire_waiter(self, grant_id: str, reason: str) -> None:
        """Fail the fetch awaiting ``grant_id`` (if still pending) — its grant expired in-queue."""
        future = self._results.get(grant_id)
        if future is not None and not future.done():
            future.set_exception(PreviewPullError(reason))  # enqueue_and_wait's finally cleans up

    async def poll(
        self, host_id: str, *, timeout_seconds: float | None = None
    ) -> PolledGrant | None:
        """Long-poll for the next NON-expired grant for ``host_id``; ``None`` on timeout (→ 204).

        An already-expired grant is dropped (and its still-awaiting fetch failed promptly) so the
        per-host queue cannot accumulate dead grants for an offline/slow host (bounded growth), and
        an agent is never handed a grant it would only refuse — mirrors the remediation JobQueue.
        """
        timeout = self._poll_timeout if timeout_seconds is None else timeout_seconds
        queue = self._queue_for(host_id)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                signed, max_bytes = await asyncio.wait_for(queue.get(), remaining)
            except TimeoutError:
                return None
            if self._expired(signed):
                self._expire_waiter(
                    signed.grant.grant_id, "grant expired before an agent claimed it"
                )
                continue
            return signed, max_bytes

    def deliver(self, *, grant_id: str, host_id: str, data: bytes) -> None:
        """Resolve the awaiting fetch for ``grant_id`` with the served bytes (host-scoped)."""
        self._resolve(grant_id=grant_id, host_id=host_id, outcome=data)

    def fail(self, *, grant_id: str, host_id: str, reason: str) -> None:
        """Resolve the awaiting fetch as a failure (the agent could not serve the file)."""
        self._resolve(grant_id=grant_id, host_id=host_id, outcome=PreviewPullError(reason))

    def _resolve(self, *, grant_id: str, host_id: str, outcome: bytes | Exception) -> None:
        future = self._results.get(grant_id)
        issued_to = self._grant_host.get(grant_id)
        if future is None or issued_to is None:
            raise PullCorrelationError("unknown or already-resolved grant")
        if issued_to != host_id:
            # A host trying to answer for a grant scoped to a different host (cross-host spoof).
            raise PullCorrelationError("result host does not match the grant's scope")
        if future.done():
            raise PullCorrelationError("grant already resolved")
        if isinstance(outcome, Exception):
            future.set_exception(outcome)
        else:
            future.set_result(outcome)


class GrantPullFetcher:
    """A :class:`~fathom.preview.service.FileFetcher` that pulls one file from its owning agent.

    Mints + signs a :class:`FileGrant` for the resolved entry, enqueues it on the
    :class:`PreviewPullQueue` for the entry's host, and returns the bytes the agent serves back.
    The single-host :class:`~fathom.preview.local_fetch.LocalFileFetcher` is the drop-in
    alternative; both satisfy the same protocol so ``PreviewService`` is unchanged.
    """

    def __init__(
        self,
        *,
        signer: GrantSigner,
        queue: PreviewPullQueue,
        grant_ttl_seconds: int,
        host_id_for: Callable[[ResolvedEntry], str] | None = None,
        now: Callable[[], datetime] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self._signer = signer
        self._queue = queue
        self._ttl = grant_ttl_seconds
        # The grant's host scope = the agent identity the owning host polls under (its catalogue
        # name; the agent verifies the grant against its own config host_id, which ingest stored as
        # the host name). Falls back to the id as a string only if the resolved name is empty.
        self._host_id_for = host_id_for or (lambda entry: entry.host_name or str(entry.host_id))
        self._now = now or (lambda: datetime.now(tz=UTC))
        self._nonce = nonce_factory or (lambda: secrets.token_hex(16))

    async def fetch(self, entry: ResolvedEntry, *, max_bytes: int) -> bytes:
        host_id = self._host_id_for(entry)
        issued = self._now()
        grant = FileGrant(
            grant_id=secrets.token_hex(16),
            entry_id=entry.entry_id,
            host_id=host_id,
            volume_id=entry.volume_id,
            inode=entry.inode,
            path=entry.path,
            content_hash=entry.content_hash,
            nonce=self._nonce(),
            issued_at=issued,
            expires_at=issued + timedelta(seconds=self._ttl),
        )
        signed = self._signer.sign(grant)
        try:
            raw = await self._queue.enqueue_and_wait(
                signed, host_id=host_id, max_bytes=max_bytes, timeout_seconds=float(self._ttl)
            )
        except PreviewPullError as exc:
            # No agent served the file in time (offline host / expired grant): a clean 504, not 500.
            raise PreviewError("preview file pull did not complete", status_code=504) from exc
        _log.info(
            "preview file pulled",
            extra={"entry_id": entry.entry_id, "host_id": host_id, "bytes": len(raw)},
        )
        return raw
