"""Single-host file fetcher — read the one resolved file directly from local disk (ADR-014).

Fathom deploys **single-host or distributed**. In the distributed topology the preview worker runs
on a different host than the data, so the file arrives via the signed single-file pull over the
agent channel (:class:`~fathom.preview.grant`). On a **single host** — core + data + preview worker
on one machine — that round-trip is unnecessary: the file is already local.
:class:`LocalFileFetcher` is the single-host :class:`~fathom.preview.service.FileFetcher`: it reads
exactly the resolved entry's bytes off local disk and hands them to the same runsc sandbox.

The read is still hedged the same way the distributed pull is:

* **server-resolved path only** — the path/inode come from the catalogue row the route already
  scope-checked, never from the client (I-7);
* **no symlink follow** — opened ``O_NOFOLLOW`` so a swapped symlink cannot redirect the read;
* **inode-anchored** — the opened fd's inode must still match the catalogue's (normalised the same
  signed-64 way the scan stored it), else the file was replaced since the scan and the fetch is
  refused (TOCTOU / path-swap). A missing (``0``) inode anchor fails closed, never reads unanchored;
* **content-hash-anchored** — when the catalogue has a full hash for the entry and the whole file
  fits the cap, the served bytes' BLAKE3 must match it; this catches an in-place rewrite (which
  preserves the inode) and guarantees the cache key (= the scanned hash) names the bytes served;
* **bounded** — at most ``max_bytes + 1`` is read so the service's input cap (413) still trips on
  an oversized file; nothing larger is ever pulled into memory.

The bytes only ever flow on to the sandbox driver — this fetcher never returns them to a caller
that would surface raw content, so the read != return boundary (ADR-014) is preserved.
"""

from __future__ import annotations

import asyncio
import os

import blake3

from fathom.backends.posix import _to_signed64
from fathom.preview.service import ResolvedEntry
from fathom.preview.types import PreviewError


class LocalFileFetcher:
    """Read one resolved catalogue entry's bytes from the local filesystem (single-host)."""

    async def fetch(self, entry: ResolvedEntry, *, max_bytes: int) -> bytes:
        return await asyncio.to_thread(self._read, entry, max_bytes)

    @staticmethod
    def _read(entry: ResolvedEntry, max_bytes: int) -> bytes:
        if not entry.inode:
            # No inode anchor → we cannot prove this is the file the catalogue resolved. Fail
            # closed rather than read whatever currently sits at the path (never read unanchored).
            raise PreviewError("preview file has no inode anchor", status_code=409)
        try:
            fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            # Missing, a symlink (O_NOFOLLOW → ELOOP), or unreadable → unavailable, not a 500.
            raise PreviewError("preview file unavailable", status_code=404) from exc
        try:
            st = os.fstat(fd)
            # The catalogue stored st_ino reinterpreted as signed-64 (_to_signed64) so large
            # NTFS/ZFS ids fit BigInteger; normalise the LIVE inode the same way before comparing,
            # else a high inode never matches and the file is wrongly refused (and a Windows-owned
            # entry would 409 forever).
            if _to_signed64(st.st_ino) != entry.inode:
                raise PreviewError(
                    "preview file changed since catalogue (inode mismatch)", status_code=409
                )
            # Read at most max_bytes + 1: the extra byte lets the service detect (and 413) an
            # oversized file without ever buffering more than the cap.
            limit = max_bytes + 1
            chunks: list[bytes] = []
            remaining = limit
            while remaining > 0:
                block = os.read(fd, min(1 << 20, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            data = b"".join(chunks)
        finally:
            os.close(fd)
        # Content-hash anchor (only when the whole file fits the cap; an oversized file is rejected
        # by the service's 413 anyway). The inode check alone can't catch an in-place rewrite —
        # truncate + rewrite preserves st_ino — so verify the served bytes' BLAKE3 against the
        # catalogue's full hash. This is the integrity guarantee the feature promises, and ensures
        # the encrypted cache (keyed on this hash) can never serve bytes that don't match it.
        if entry.content_hash and len(data) <= max_bytes:
            if blake3.blake3(data).hexdigest() != entry.content_hash:
                raise PreviewError(
                    "preview file content changed since catalogue (hash mismatch)",
                    status_code=409,
                )
        return data
