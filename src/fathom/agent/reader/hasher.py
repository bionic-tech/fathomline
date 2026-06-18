"""Progressive content hashing for full-bit mode (ADD 02 §Mode 2).

BLAKE3 over a backend's ``AsyncReader``, in two cheap stages so the dedup engine opens as
few bytes as correctness allows: a 4 KiB head+tail *partial* digest first, and only when
partials collide a *full* digest. Reads are offloaded to threads by the backend, so the
event loop is never blocked. This module only reads bytes — it never writes.
"""

from __future__ import annotations

import blake3

from fathom.backends.base import StorageBackend

HEAD_TAIL_BYTES = 4096
FULL_CHUNK_BYTES = 1 << 20


async def partial_digest(backend: StorageBackend, path: str, size: int) -> str:
    """Return the BLAKE3 of the file's first and last ``HEAD_TAIL_BYTES`` (ADD 02)."""
    reader = await backend.open_for_hash(path)
    try:
        h = blake3.blake3()
        h.update(await reader.read(HEAD_TAIL_BYTES))
        if size > HEAD_TAIL_BYTES:
            await reader.seek(max(HEAD_TAIL_BYTES, size - HEAD_TAIL_BYTES))
            h.update(await reader.read(HEAD_TAIL_BYTES))
        return h.hexdigest()
    finally:
        await reader.close()


async def full_digest(backend: StorageBackend, path: str) -> str:
    """Return the full-content BLAKE3 of ``path`` (streamed, bounded memory)."""
    reader = await backend.open_for_hash(path)
    try:
        h = blake3.blake3()
        while True:
            block = await reader.read(FULL_CHUNK_BYTES)
            if not block:
                break
            h.update(block)
        return h.hexdigest()
    finally:
        await reader.close()


class BackendHasher:
    """Adapts a ``StorageBackend`` to the dedup engine's ``Hasher`` protocol."""

    def __init__(self, backend: StorageBackend) -> None:
        self._backend = backend

    async def partial(self, path: str, size: int) -> str:
        return await partial_digest(self._backend, path, size)

    async def full(self, path: str) -> str:
        return await full_digest(self._backend, path)
