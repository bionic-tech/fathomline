"""Preview render orchestration (ADR-014; preview-worker service).

The :class:`PreviewService` is the in-core orchestrator the worker task / route uses. For one
resolved catalogue entry it:

1. derives the **cache key** from the entry's content hash + render params, and returns the
   encrypted cached derived artifact on a hit (no raw bytes, no re-render);
2. on a miss, pulls **exactly one file** via the injected :class:`FileFetcher` — the signed
   single-file pull over the agent-initiated channel (owner ruling; no broad mount), bounded by a
   max-input guard;
3. detects the type by **magic bytes** (not extension), refusing unsupported/deferred types;
4. hands the raw bytes to the :class:`~fathom.preview.sandbox.SandboxDriver` — one ephemeral
   ``runsc`` container per render — which returns **derived artifacts only**;
5. stores the encrypted result in the cache and records a metadata-only ``preview_cache_meta``
   row (never the bytes), then returns the result.

The service never decodes content itself (the sandbox does) and never returns raw bytes (every
artifact is derived). Audit-before-serve and the RBAC scope gate live in the route/worker; the
service is the pure render+cache pipeline so it is fully unit-testable with a fake driver/fetcher.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from fathom.logging import get_logger
from fathom.preview.cache import EncryptedLruCache, derive_cache_key
from fathom.preview.sandbox import SandboxDriver
from fathom.preview.types import (
    PreviewError,
    PreviewResult,
    ResourceCaps,
    detect_type,
)

_log = get_logger("fathom.preview.service")

# How much of the file to sniff for magic-byte type detection (never the whole file in core).
_SNIFF_BYTES = 4096


@dataclass(frozen=True, slots=True)
class ResolvedEntry:
    """The server-resolved identity of a catalogue entry to preview (never client-supplied).

    Resolved from ``fs_entry`` by the route: the host/volume/path/inode/content-hash come from the
    catalogue, so the preview path never acts on an attacker-supplied path (interfaces).
    """

    entry_id: int
    host_id: int
    volume_id: int
    path: str
    inode: int
    content_hash: str | None
    # The owning host's catalogue *name* (= the agent's enrolment identity / poll scope). Used by
    # the distributed GrantPullFetcher to scope the grant to the one agent that may serve the file;
    # empty for the local-fetch path (which never mints a grant). Defaulted so existing call sites
    # and the single-host path are unaffected.
    host_name: str = ""


class FileFetcher(Protocol):
    """Fetch exactly ONE file's raw bytes for ``entry`` (the signed single-file pull).

    The production implementation mints a signed, nonce'd, scope-checked, short-TTL
    :class:`~fathom.preview.grant.FileGrant` and redeems it over the agent-initiated mTLS channel
    so the agent serves only that one file (owner ruling; no new inbound port, no broad mount). A
    fetch that cannot deliver the file raises :class:`~fathom.preview.types.PreviewError`.
    """

    async def fetch(self, entry: ResolvedEntry, *, max_bytes: int) -> bytes: ...


class PreviewService:
    """Cache-or-render pipeline for one entry → derived artifacts (ADR-014)."""

    def __init__(
        self,
        *,
        cache: EncryptedLruCache,
        driver: SandboxDriver,
        fetcher: FileFetcher,
        caps: ResourceCaps,
        max_input_bytes: int,
        cache_ttl_seconds: int,
    ) -> None:
        self._cache = cache
        self._driver = driver
        self._fetcher = fetcher
        self._caps = caps
        self._max_input_bytes = max_input_bytes
        self._cache_ttl = cache_ttl_seconds

    def _render_params(self) -> str:
        """A stable string capturing the render parameters that affect the output (cache key)."""
        return f"v1:pages={self._caps.max_pages}"

    async def render(self, entry: ResolvedEntry, *, job_id: str) -> tuple[PreviewResult, int]:
        """Return ``(result, cached_size)`` for ``entry`` — a cache hit or a fresh sandbox render.

        ``cached_size`` is the size of the encrypted artifact at rest (the meta row's
        ``artifact_size`` — never the raw content size). Raises
        :class:`~fathom.preview.types.PreviewError` on unsupported/oversized/failed renders so the
        route maps it to a sanitised problem+json.
        """
        cache_key: str | None = None
        if entry.content_hash:
            cache_key = derive_cache_key(
                content_hash=entry.content_hash, render_params=self._render_params()
            )
            hit = await self._cache.get(cache_key)
            if hit is not None:
                # Cache hit: encrypted derived artifact, no raw fetch, no re-render (I-8).
                return hit.model_copy(update={"entry_id": entry.entry_id}), 0

        # Cache miss → signed single-file pull of exactly this one file (owner ruling).
        raw = await self._fetcher.fetch(entry, max_bytes=self._max_input_bytes)
        if len(raw) > self._max_input_bytes:
            raise PreviewError("file exceeds preview input cap", status_code=413)

        detected = detect_type(raw[:_SNIFF_BYTES])
        if detected is None:
            # Unknown / deferred (video/audio/archive) → graceful, not a 500 (test_plan).
            raise PreviewError("unsupported preview type", status_code=415)

        artifacts = await self._driver.run(raw, detected=detected, caps=self._caps, job_id=job_id)
        result = PreviewResult(
            entry_id=entry.entry_id,
            type=detected,
            artifacts=artifacts,
            cache_hit=False,
            sandbox_job_id=job_id,
        )
        cached_size = 0
        if cache_key is not None:
            cached_size = await self._cache.put(cache_key, result, ttl_seconds=self._cache_ttl)
        _log.info(
            "preview rendered",
            extra={
                "entry_id": entry.entry_id,
                "type": detected.value,
                "job_id": job_id,
                "artifacts": len(artifacts),
            },
        )
        return result, cached_size
