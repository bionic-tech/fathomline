"""SFTP storage backend — async-native metadata walk over SSH (ADR-004, ADD 02 §Mode 2).

SFTP is served by :mod:`asyncssh` — chosen over paramiko because it is **async-native** and so
never blocks the event loop (async-patterns gate; design_questions §2). The backend is
metadata-only: it ``stat``s the remote tree and reports capacity via the
``statvfs@openssh.com`` extension. It inherits the two hard remote invariants from
:class:`~fathom.backends.remote._RemoteBackendBase`:

* :meth:`open_for_hash` raises :class:`~fathom.backends.base.FullBitUnsupportedError` — full-bit
  content hashing never runs over SFTP (ADD 02 line 63);
* :meth:`is_busy` is ``False`` (no local backing array to resilver).

Host-key verification is **on by default**; ``known_hosts`` checking is only relaxed behind the
loud lab-only ``lab_insecure`` flag (security_constraints, code-quality #6). SSH key or password
material comes only from the pluggable secret backend (ADR-010) via a ``secret_provider`` —
never from code or config. The transport is injectable (a
:class:`~fathom.backends.remote.RemoteTransport`) so the walk/mapping logic is unit-tested
against a fake without a live SSH server (the lazy-imported :mod:`asyncssh` transport).
"""

from __future__ import annotations

import stat as stat_mod
from collections.abc import AsyncIterator, Collection

from fathom.agent.config import RemoteBackendConfig
from fathom.backends.base import FsEntry, VolumeInfo
from fathom.backends.remote import (
    MissingClientLibraryError,
    RemoteBackendError,
    RemoteCreds,
    RemoteStat,
    RemoteTransport,
    SecretProvider,
    _RemoteBackendBase,
    remote_walk,
    resolve_creds,
)
from fathom.logging import get_logger

_log = get_logger("fathom.backends.sftp")

_DEFAULT_SFTP_PORT = 22


class SftpBackend(_RemoteBackendBase):
    """A metadata-only :class:`~fathom.backends.base.StorageBackend` over SFTP (structural)."""

    protocol = "sftp"

    def __init__(
        self,
        config: RemoteBackendConfig,
        *,
        secret_provider: SecretProvider | None = None,
        transport: RemoteTransport | None = None,
    ) -> None:
        if config.protocol != "sftp":
            raise ValueError(f"SftpBackend requires protocol='sftp', got {config.protocol!r}")
        self._config = config
        self._secret_provider = secret_provider
        self._injected_transport = transport
        self._transport: RemoteTransport | None = transport

    def supports(self, mountpoint: str) -> bool:
        """True when this backend's configured target matches ``mountpoint`` (the mount key)."""
        return mountpoint == self._config.mount_key

    def _creds(self) -> RemoteCreds:
        """Resolve SSH creds from the secret backend (ADR-010); count-only logging."""
        creds = resolve_creds(
            username=self._config.username,
            password_ref=self._config.password_ref,
            private_key_ref=self._config.private_key_ref,
            secret_provider=self._secret_provider,
        )
        _log.info(
            "resolved sftp credentials",
            extra={
                "host": self._config.host,
                "has_password": creds.has_password,
                "has_key": creds.has_key,
            },
        )
        return creds

    async def _ensure_transport(self) -> RemoteTransport:
        if self._transport is not None:
            return self._transport
        creds = self._creds()
        self._transport = await _connect_asyncssh(self._config, creds)
        return self._transport

    async def volume_info(self, mountpoint: str) -> VolumeInfo:
        """Report capacity via ``statvfs@openssh.com``; ``transport='network'`` (ADD 02)."""
        transport = await self._ensure_transport()
        total, used, free = await transport.statvfs(self._config.remote_path)
        return VolumeInfo(
            # Synthetic POSIX-absolute mountpoint (ADR-029); pretty sftp://… as the display label.
            mountpoint=self._config.catalogue_mount,
            display_name=self._config.mount_key,
            fs_type="sftp",
            total=total,
            used=used,
            free=free,
            device=f"{self._config.host}:{self._config.remote_path}",
            transport="network",
            raid_role=None,
            dataset=None,
        )

    async def walk(
        self,
        root: str,
        *,
        follow_symlinks: bool = False,
        one_filesystem: bool = True,
        exclude: Collection[str] = (),
    ) -> AsyncIterator[FsEntry]:
        """Metadata-only recursive ``stat`` walk over SFTP (never reads file contents).

        ``one_filesystem`` is meaningless across a network share (there are no nested local mounts
        to cross) and is accepted only for protocol parity. The walk is delegated to the shared
        :func:`~fathom.backends.remote.remote_walk` so SMB and SFTP descend identically. ``exclude``
        (ADR-034) is local-FS subtree pruning; accepted for parity but not applied to remote shares.
        """
        transport = await self._ensure_transport()
        start = self._config.remote_path if root == self._config.mount_key else root
        async for entry in remote_walk(
            transport,
            start,
            follow_symlinks=follow_symlinks,
            log_component=_log.name,
            mount=self._config.catalogue_mount,
            remote_root=self._config.remote_path,
        ):
            yield entry

    async def close(self) -> None:
        """Release the SFTP session if this backend opened it (idempotent)."""
        if self._transport is not None and self._transport is not self._injected_transport:
            await self._transport.close()
            self._transport = None


async def _connect_asyncssh(
    config: RemoteBackendConfig, creds: RemoteCreds
) -> RemoteTransport:  # pragma: no cover - requires a live SSH server + optional dep
    """Open a real :mod:`asyncssh` SFTP session (lazy-imported; base runtime dep).

    Host-key verification is on unless ``verify=False`` is set (``known_hosts=None`` disables it,
    the loud lab-only path). Key/password material is passed from the resolved creds and never
    logged. Raises :class:`MissingClientLibraryError` if :mod:`asyncssh` is not installed.
    """
    try:
        import asyncssh
    except ImportError as exc:  # the optional transport is not installed
        raise MissingClientLibraryError(
            "asyncssh is required for the SFTP backend but is not importable"
        ) from exc

    # known_hosts=None disables host-key verification (the loud, lab-only path); () means "verify
    # against the system known_hosts". asyncssh's overloads don't model this cleanly, so this thin
    # live-only adapter passes the value through untyped.
    known_hosts = () if config.verify else None
    private_key = creds.private_key
    client_keys = [asyncssh.import_private_key(private_key)] if private_key is not None else None
    try:
        conn = await asyncssh.connect(
            host=config.host,
            port=config.port or _DEFAULT_SFTP_PORT,
            username=creds.username,
            password=creds.password,
            client_keys=client_keys,
            known_hosts=known_hosts,
        )
        sftp = await conn.start_sftp_client()
    except (OSError, asyncssh.Error) as exc:
        raise RemoteBackendError(f"sftp connection to {config.host!r} failed: {exc}") from exc
    return _AsyncsshSftpTransport(conn, sftp)


class _AsyncsshSftpTransport:  # pragma: no cover - thin adapter over the live asyncssh client
    """Adapts a live :mod:`asyncssh` SFTP client to the :class:`RemoteTransport` Protocol."""

    def __init__(self, conn: object, sftp: object) -> None:
        self._conn = conn
        self._sftp = sftp

    async def listdir(self, path: str) -> list[RemoteStat]:
        names = await self._sftp.readdir(path)  # type: ignore[attr-defined]
        out: list[RemoteStat] = []
        for entry in names:
            filename = entry.filename
            if filename in {".", ".."}:
                continue
            attrs = entry.attrs
            full = path.rstrip("/") + "/" + filename
            mode = attrs.permissions or 0
            out.append(
                _LiveStat(
                    name=filename,
                    path=full,
                    is_dir=stat_mod.S_ISDIR(mode),
                    is_symlink=stat_mod.S_ISLNK(mode),
                    size=int(attrs.size or 0),
                    mtime=float(attrs.mtime or 0.0),
                    uid=int(attrs.uid or 0),
                    gid=int(attrs.gid or 0),
                )
            )
        return out

    async def statvfs(self, path: str) -> tuple[int, int, int]:
        vfs = await self._sftp.statvfs(path)  # type: ignore[attr-defined]
        total = vfs.f_blocks * vfs.f_frsize
        free = vfs.f_bavail * vfs.f_frsize
        used = (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize
        return total, used, free

    async def close(self) -> None:
        self._sftp.exit()  # type: ignore[attr-defined]
        self._conn.close()  # type: ignore[attr-defined]
        await self._conn.wait_closed()  # type: ignore[attr-defined]


class _LiveStat:  # pragma: no cover - simple value carrier for the live transport
    """A concrete :class:`~fathom.backends.remote.RemoteStat` built from live SFTP attrs."""

    def __init__(
        self,
        *,
        name: str,
        path: str,
        is_dir: bool,
        is_symlink: bool,
        size: int,
        mtime: float,
        uid: int,
        gid: int,
    ) -> None:
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.is_symlink = is_symlink
        self.size = size
        self.mtime = mtime
        self.uid = uid
        self.gid = gid
