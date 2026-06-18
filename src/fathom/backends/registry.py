"""Backend selection by capability (ADR-004).

A scan target is matched to the first registered backend whose ``supports()`` returns
True. Specialised backends (ZFS, NTFS/exFAT, SMB, SFTP) register ahead of the generic POSIX
fallback, so the most filesystem-aware plugin wins (first-match-wins). The
:func:`build_default_registry` factory encodes that ordering once so the runner never has to.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from fathom.backends.base import StorageBackend
from fathom.logging import get_logger

if TYPE_CHECKING:
    from fathom.adapters.base import PlatformAdapter
    from fathom.agent.config import RemoteBackendConfig
    from fathom.backends.remote import SecretProvider

_log = get_logger("fathom.backends.registry")


class NoBackendError(RuntimeError):
    """Raised when no registered backend supports a mountpoint."""


class BackendRegistry:
    """An ordered registry of ``StorageBackend`` plugins; first match wins."""

    def __init__(self) -> None:
        self._backends: list[StorageBackend] = []

    def register(self, backend: StorageBackend) -> None:
        """Append ``backend`` to the resolution order (registered earlier = higher priority)."""
        if not isinstance(backend, StorageBackend):
            raise TypeError(f"{backend!r} does not satisfy the StorageBackend protocol")
        self._backends.append(backend)
        _log.info("backend registered", extra={"backend": type(backend).__name__})

    def resolve(self, mountpoint: str) -> StorageBackend:
        """Return the highest-priority backend that supports ``mountpoint``."""
        for backend in self._backends:
            if backend.supports(mountpoint):
                return backend
        raise NoBackendError(f"no registered backend supports {mountpoint!r}")

    @property
    def backends(self) -> tuple[StorageBackend, ...]:
        """The registered backends in resolution order (read-only view, for tests/introspection)."""
        return tuple(self._backends)


def build_default_registry(
    adapter: PlatformAdapter | None = None,
    *,
    pool: str | None = None,
    walk_concurrency: int = 4,
    remote_targets: Sequence[RemoteBackendConfig] = (),
    secret_provider: SecretProvider | None = None,
) -> BackendRegistry:
    """Build the production registry with specialised backends ahead of POSIX (ADR-004).

    Resolution order (first-match-wins):

    1. :class:`~fathom.backends.windows.WindowsBackend` — **registered only when running on
       Windows** (``os.name == "nt"``); wins on every local Windows path (ADR-027 W1).
    2. :class:`~fathom.backends.zfs.ZfsBackend` — wins on ZFS mounts; takes topology / resilver
       state from ``adapter``/``pool`` when wired (ADD 04), else degrades to statvfs/zpool.
    3. :class:`~fathom.backends.ntfs.NtfsExfatBackend` — wins on NTFS/exFAT/FAT mounts (the
       *POSIX-mounted* NTFS case, distinct from the native Windows backend above).
    4. one remote backend per entry in ``remote_targets`` — SMB / SFTP / rclone
       (:class:`~fathom.backends.smb.SmbBackend`, :class:`~fathom.backends.sftp.SftpBackend`,
       :class:`~fathom.backends.rclone.RcloneBackend`), each matching only its own ``mount_key``
       (SMB/SFTP resolve credentials through ``secret_provider``, ADR-010; rclone uses the host's
       rclone.conf, ADR-028).
    5. :class:`~fathom.backends.posix.PosixBackend` — the generic fallback, **always last**.

    The remote backends are deliberately last among the specialised set: they match by an explicit
    ``mount_key`` (never a local path) so ordering against ZFS/NTFS is moot, but POSIX must remain
    the final fallback so any unmatched local path still resolves (the documented invariant).
    """
    import os

    from fathom.backends.ntfs import NtfsExfatBackend
    from fathom.backends.posix import PosixBackend
    from fathom.backends.rclone import RcloneBackend
    from fathom.backends.sftp import SftpBackend
    from fathom.backends.smb import SmbBackend
    from fathom.backends.zfs import ZfsBackend

    registry = BackendRegistry()
    if os.name == "nt":
        from fathom.backends.windows import WindowsBackend

        registry.register(WindowsBackend(walk_concurrency=walk_concurrency))
    registry.register(ZfsBackend(walk_concurrency=walk_concurrency, adapter=adapter, pool=pool))
    registry.register(NtfsExfatBackend(walk_concurrency=walk_concurrency))
    for target in remote_targets:
        if target.protocol == "smb":
            registry.register(SmbBackend(target, secret_provider=secret_provider))
        elif target.protocol == "rclone":
            registry.register(RcloneBackend(target))  # auth via rclone.conf, no secret_provider
        else:
            registry.register(SftpBackend(target, secret_provider=secret_provider))
    registry.register(PosixBackend(walk_concurrency=walk_concurrency))
    return registry
