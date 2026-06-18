"""Encrypted, bounded-LRU, TTL preview cache (ADR-014; STRIDE I-8; data-protection §3/§4/§7).

The preview cache holds **no raw bytes** — only encrypted DERIVED artifacts (a downscaled
thumbnail, a page-raster, an extracted text snippet). It is:

* **encrypted at rest** (Fernet / AES-128-CBC + HMAC) independently of the catalogue, with the
  key sourced from the secret backend (ADR-010); a dev/test process without a provisioned key
  gets an ephemeral per-process key (still encrypted, just not durable across a restart — fine
  for a 30-min-TTL cache);
* **bounded LRU** by entry count, and **TTL'd at 30 minutes**, evicting on whichever comes first;
* keyed by ``content_hash`` + render params, so two requests for the same file hit the same
  entry and a re-render is avoided.

The companion :class:`~fathom.core.catalogue.preview_cache_meta.PreviewCacheMeta` row records
*metadata only* (content hash, type, size, expiry, hit/miss) — never the artifact bytes. The
bytes live here, encrypted; the meta table never holds them (data_model_changes).
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

from fathom.preview.types import PreviewResult


def derive_cache_key(*, content_hash: str, render_params: str) -> str:
    """Build the cache key from the content hash + a stable render-params string.

    Keying off the *content* hash (not entry id) means two catalogue entries that are byte
    identical share one cached render, and a file whose bytes changed gets a fresh key.
    """
    return f"{content_hash}:{render_params}"


@dataclass(slots=True)
class _Entry:
    """One encrypted cache entry: ciphertext + its absolute expiry (monotonic seconds)."""

    ciphertext: bytes
    expires_at: float
    size: int


class EncryptedLruCache:
    """A bounded-LRU, TTL, at-rest-encrypted cache for derived preview artifacts (I-8).

    Thread/async-safe via an ``asyncio.Lock``. Values are serialised to JSON and Fernet-encrypted
    before storage, so the in-memory (and any future on-disk) representation never contains
    plaintext derived content (data-protection §4: "preview cache encrypted independently").
    """

    def __init__(
        self,
        *,
        key: bytes,
        max_entries: int,
        ttl_seconds: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._fernet = Fernet(key)
        self._max_entries = max_entries
        self._ttl = ttl_seconds
        self._clock = clock or time.monotonic
        self._store: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    @classmethod
    def from_key_material(
        cls, key_material: str | None, *, max_entries: int, ttl_seconds: int
    ) -> EncryptedLruCache:
        """Build a cache from a urlsafe-base64 Fernet key, or an ephemeral one when ``None``.

        A provisioned key (from the secret backend, ADR-010) survives restarts; ``None`` (dev/
        test) generates a per-process key — the cache stays encrypted, the key just is not durable
        (acceptable for a 30-min-TTL cache that re-renders on miss).
        """
        key = key_material.encode("ascii") if key_material else Fernet.generate_key()
        return cls(key=key, max_entries=max_entries, ttl_seconds=ttl_seconds)

    async def get(self, key: str) -> PreviewResult | None:
        """Return the decrypted, non-expired result for ``key`` (LRU-touch), or ``None``."""
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry.expires_at <= self._clock():
                # TTL expired → evict and miss (never serve stale content; data-protection §7).
                del self._store[key]
                self._misses += 1
                return None
            self._store.move_to_end(key)  # mark most-recently-used
            self._hits += 1
            try:
                plaintext = self._fernet.decrypt(entry.ciphertext)
            except InvalidToken:  # pragma: no cover — key rotation/corruption → treat as miss
                del self._store[key]
                self._misses += 1
                return None
            return PreviewResult.model_validate_json(plaintext).model_copy(
                update={"cache_hit": True}
            )

    async def put(self, key: str, result: PreviewResult, *, ttl_seconds: int | None = None) -> int:
        """Encrypt and store ``result`` under ``key``, evicting LRU entries past the bound.

        Returns the ciphertext size (the value the meta row records — bytes-at-rest, not raw
        content). ``ttl_seconds`` overrides the default 30-min TTL for this entry if given.
        """
        plaintext = result.model_dump_json().encode("utf-8")
        ciphertext = self._fernet.encrypt(plaintext)
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl
        async with self._lock:
            self._store[key] = _Entry(
                ciphertext=ciphertext,
                expires_at=self._clock() + ttl,
                size=len(ciphertext),
            )
            self._store.move_to_end(key)
            # Bounded LRU: evict oldest until within the entry cap (whichever evicts first wins
            # against the TTL — data-protection §7).
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)
        return len(ciphertext)

    @property
    def stats(self) -> tuple[int, int]:
        """Return ``(hits, misses)`` accounting for the cache (meta hit/miss bookkeeping)."""
        return self._hits, self._misses

    async def clear(self) -> None:
        """Drop all entries (test teardown / explicit flush)."""
        async with self._lock:
            self._store.clear()
