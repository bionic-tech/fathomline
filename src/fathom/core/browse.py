"""Signed live directory-browse request (ADR-034 Phase 2; reuses ADR-011/014 signing primitives).

Live browse lets an operator pick scan roots by listing a host's real directories — *including
directories that have not been scanned yet*. Enrolled agents are push-only, so this rides the same
agent-initiated channel as the preview pull (ADR-014): the agent long-polls the core for a signed
:class:`BrowseRequest`, verifies it against a **pinned core public key**, lists exactly **one**
directory (metadata only — names, types, sizes, counts; **never file contents**), and posts the
result back. It is **read-only** and, unlike the remediation listen daemon (ADR-025), does **not**
require ``write_enabled`` / ``quarantine_dir`` — browse trust ≠ write trust.

This mirrors :class:`~fathom.preview.grant.FileGrant`: a frozen, ``extra='forbid'`` envelope with a
canonical byte serialization the Ed25519 signature is computed over, a single-use ``nonce``, an
``issued_at``/``expires_at`` window, and the target ``host_id`` scope. Verification is fail-closed
on every axis (signature → time window → host scope → nonce), like ``verify_grant``/``verify_job``.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

from fathom.logging import get_logger

if TYPE_CHECKING:
    from fathom.core.remediation.signing import NonceStore

_log = get_logger("fathom.core.browse")

# Default bounds for one browse listing (the operator endpoint may lower, never raise, these).
DEFAULT_MAX_ENTRIES = 2000  # cap on entries returned for one directory (avoids a huge listing)
DEFAULT_SIZE_MAX_ENTRIES = 200_000  # per child dir: cap the bounded subtree-size walk
DEFAULT_SIZE_BUDGET_MS = 1500  # per child dir: time budget for the bounded subtree-size walk


class BrowseVerificationError(Exception):
    """A browse request failed signature / expiry / scope verification (fail-closed; no FS read)."""


class BrowseReplayError(BrowseVerificationError):
    """A browse request's nonce was already consumed — a replay (T-3). Subclass so callers may catch
    either the specific replay or any verification failure."""


class BrowseRequest(BaseModel):
    """A scoped, time-boxed, single-use authorisation to list exactly ONE directory (read-only).

    The core signs this and the agent serves only the directory ``path`` names, after verifying the
    signature (over :meth:`canonical_bytes`) covers every field — so a widened path / extended
    expiry / swapped host invalidates it. The listing returns metadata only; file *contents* never
    cross the channel. ``with_sizes`` asks the agent to compute a BOUNDED subtree size + file-count
    per child dir (capped by ``size_max_entries`` and ``size_budget_ms``, flagged when truncated).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=64)
    host_id: str = Field(min_length=1, max_length=255)  # the one host that may serve this listing
    path: str = Field(min_length=1, max_length=4096)  # the directory to list (absolute)
    max_entries: int = Field(default=DEFAULT_MAX_ENTRIES, ge=1, le=50_000)
    with_sizes: bool = Field(default=True)  # compute bounded per-child subtree size + count
    size_max_entries: int = Field(default=DEFAULT_SIZE_MAX_ENTRIES, ge=0, le=5_000_000)
    size_budget_ms: int = Field(default=DEFAULT_SIZE_BUDGET_MS, ge=0, le=30_000)
    nonce: str = Field(min_length=16, max_length=128)  # single-use; 128-bit+ CSPRNG hex
    issued_at: datetime
    expires_at: datetime

    def canonical_bytes(self) -> bytes:
        """Return the stable byte string the signature is computed over (sorted, compact).

        Any field change (a widened path, an extended expiry, a swapped host) changes these bytes
        and invalidates the signature — the agent then refuses the listing.
        """
        payload: dict[str, object] = {
            "request_id": self.request_id,
            "host_id": self.host_id,
            "path": self.path,
            "max_entries": self.max_entries,
            "with_sizes": self.with_sizes,
            "size_max_entries": self.size_max_entries,
            "size_budget_ms": self.size_budget_ms,
            "nonce": self.nonce,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SignedBrowseRequest(BaseModel):
    """A :class:`BrowseRequest` plus its detached Ed25519 signature and key id (base64; ADR-010)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request: BrowseRequest
    key_id: str = Field(min_length=1)
    algorithm: str = Field(default="ed25519")
    signature: str = Field(min_length=1)  # base64-encoded


class BrowseEntry(BaseModel):
    """One directory entry in a browse listing — metadata only, never file contents."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    path: str
    is_dir: bool
    is_symlink: bool
    size: int = Field(ge=0)  # own size (st_size); for dirs this is the dir node size, not subtree
    mtime: float
    # Present only for child directories when with_sizes was set: a BOUNDED subtree rollup.
    subtree_size: int | None = Field(default=None, ge=0)
    subtree_file_count: int | None = Field(default=None, ge=0)
    subtree_truncated: bool = Field(default=False)  # the size cap / time budget was hit


class BrowseVolume(BaseModel):
    """One mounted volume from a live ``df`` probe (the Deploy df-style dropdown source)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mountpoint: str
    fs_type: str = ""
    total: int = Field(default=0, ge=0)
    used: int = Field(default=0, ge=0)
    free: int = Field(default=0, ge=0)


class BrowseResult(BaseModel):
    """The agent's reply to a :class:`BrowseRequest`: the listing of one directory (or an error)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=64)
    path: str
    entries: list[BrowseEntry] = Field(default_factory=list)
    truncated: bool = Field(default=False)  # the directory had more than max_entries
    error: str | None = Field(default=None, max_length=512)  # e.g. ENOENT/EACCES (no raw stack)


class ClaimedBrowse(BaseModel):
    """The agent-poll response: a signed browse request the agent should serve (else 204 idle)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signed_request: SignedBrowseRequest


class BrowseSigner:
    """Core-side Ed25519 signer for browse requests (a dedicated browse key; ADR-010).

    The same Ed25519 primitive as the remediation/preview signers (owner ruling: do not invent a
    second signing scheme). The browse key is DISTINCT from the orchestrator (remediation) key —
    browse trust ≠ write trust — and is injected from the secret backend, never read from code here.
    """

    algorithm = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey, *, key_id: str) -> None:
        self._private_key = private_key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, request: BrowseRequest) -> SignedBrowseRequest:
        signature = self._private_key.sign(request.canonical_bytes())
        return SignedBrowseRequest(
            request=request,
            key_id=self._key_id,
            algorithm="ed25519",
            signature=base64.b64encode(signature).decode("ascii"),
        )


class BrowseVerifier:
    """Agent-side Ed25519 verifier — trusts exactly one core browse public key (key_id)."""

    algorithm = "ed25519"

    def __init__(self, public_key: Ed25519PublicKey, *, key_id: str) -> None:
        self._public_key = public_key
        self._key_id = key_id

    def verify_signature(self, signed: SignedBrowseRequest) -> bool:
        if signed.algorithm != "ed25519" or signed.key_id != self._key_id:
            return False  # algorithm/key downgrade or unknown key → reject (fail-closed)
        try:
            self._public_key.verify(
                base64.b64decode(signed.signature), signed.request.canonical_bytes()
            )
        except (InvalidSignature, ValueError):
            return False
        return True


def _as_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp (round-trips can drop tzinfo) to UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class BrowsePullError(RuntimeError):
    """The owning agent did not serve the listing within the request window (fail-closed → 504)."""


class BrowseCorrelationError(RuntimeError):
    """A served result could not be matched to an awaiting browse (spoofed / cross-host / replayed).

    Raised when a delivery names a ``request_id`` that was never issued, was already resolved, or is
    posted by a host other than the one the request was scoped to. The route maps it to a 409.
    """


class BrowsePullQueue:
    """Per-host signed browse-request rendezvous with awaited result correlation (core side).

    Mirrors :class:`~fathom.preview.pull.PreviewPullQueue`: the operator ``enqueue_and_wait``s
    a signed :class:`BrowseRequest`; the owning agent long-polls ``poll`` for it, verifies it
    fail-closed, lists the one directory, and ``deliver``s the :class:`BrowseResult` back, resolving
    the awaiting call. A result from any host other than the request's scope is refused.
    """

    def __init__(
        self,
        *,
        poll_timeout_seconds: float = 25.0,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._queues: dict[str, asyncio.Queue[SignedBrowseRequest]] = {}
        self._results: dict[str, asyncio.Future[BrowseResult]] = {}
        self._request_host: dict[str, str] = {}
        self._poll_timeout = poll_timeout_seconds
        self._now = now or (lambda: datetime.now(tz=UTC))

    def _queue_for(self, host_id: str) -> asyncio.Queue[SignedBrowseRequest]:
        return self._queues.setdefault(host_id, asyncio.Queue())

    async def enqueue_and_wait(
        self, signed: SignedBrowseRequest, *, host_id: str, timeout_seconds: float
    ) -> BrowseResult:
        """Enqueue ``signed`` for ``host_id`` and block on the agent's correlated listing result.

        Raises :class:`BrowsePullError` if no agent delivers within ``timeout_seconds`` (set by the
        caller to the request TTL, so a timed-out request is also expired).
        """
        request_id = signed.request.request_id
        if request_id in self._results:
            raise BrowseCorrelationError("duplicate request_id already in flight")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[BrowseResult] = loop.create_future()
        self._results[request_id] = future
        self._request_host[request_id] = host_id
        self._queue_for(host_id).put_nowait(signed)
        try:
            return await asyncio.wait_for(future, timeout=timeout_seconds)
        except TimeoutError as exc:
            raise BrowsePullError("browse listing timed out") from exc
        finally:
            self._results.pop(request_id, None)
            self._request_host.pop(request_id, None)

    def _expired(self, signed: SignedBrowseRequest) -> bool:
        return _as_utc(signed.request.expires_at) <= self._now()

    async def poll(
        self, host_id: str, *, timeout_seconds: float | None = None
    ) -> SignedBrowseRequest | None:
        """Long-poll for the next NON-expired request for ``host_id``; ``None`` on timeout."""
        timeout = self._poll_timeout if timeout_seconds is None else timeout_seconds
        queue = self._queue_for(host_id)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                signed = await asyncio.wait_for(queue.get(), remaining)
            except TimeoutError:
                return None
            if self._expired(signed):
                future = self._results.get(signed.request.request_id)
                if future is not None and not future.done():
                    future.set_exception(BrowsePullError("request expired before being claimed"))
                continue
            return signed

    def deliver(self, *, host_id: str, result: BrowseResult) -> None:
        """Resolve the awaiting browse for ``result.request_id`` with the listing (host-scoped)."""
        future = self._results.get(result.request_id)
        issued_to = self._request_host.get(result.request_id)
        if future is None or issued_to is None:
            raise BrowseCorrelationError("unknown or already-resolved browse request")
        if issued_to != host_id:
            raise BrowseCorrelationError("result host does not match the request's scope")
        if future.done():
            raise BrowseCorrelationError("browse request already resolved")
        future.set_result(result)


async def verify_browse_request(
    signed: SignedBrowseRequest,
    *,
    verifier: BrowseVerifier,
    nonce_store: NonceStore,
    expected_host_id: str,
    now: datetime | None = None,
) -> BrowseRequest:
    """Verify a signed browse request on **every** axis before returning it (fail-closed).

    Order mirrors ``verify_grant``/``verify_job``: signature → time window → host scope are checked
    *before* the nonce is consumed, so a tampered/expired/out-of-scope request never burns a nonce.
    The nonce is consumed last, atomically (insert-or-fail), so a replay raises
    :class:`BrowseReplayError` (T-3). Only after all of this does the agent list the directory.

    Raises:
        BrowseVerificationError: bad signature, expired/not-yet-valid, or wrong host scope.
        BrowseReplayError: the nonce has already been consumed (a replay).
    """
    if not verifier.verify_signature(signed):
        raise BrowseVerificationError("browse request signature verification failed")
    request = signed.request
    current = now or datetime.now(tz=UTC)
    if _as_utc(request.expires_at) <= current:
        raise BrowseVerificationError("browse request has expired")
    if _as_utc(request.issued_at) > current:
        raise BrowseVerificationError("browse request is not yet valid")
    if request.host_id != expected_host_id:
        raise BrowseVerificationError(
            f"browse host scope {request.host_id!r} does not match this agent {expected_host_id!r}"
        )
    if not await nonce_store.consume(request.nonce, job_id=request.request_id):
        raise BrowseReplayError(f"browse nonce already consumed (replay): {request.nonce}")
    return request
