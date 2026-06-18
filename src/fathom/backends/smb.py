"""SMB storage backend — metadata walk over CIFS/SMB (ADR-004, ADD 02 §Mode 2).

SMB is served by the pure-Python :mod:`smbprotocol` / :mod:`smbclient` (owner ruling). That
client is **blocking**, so every call is wrapped in :func:`asyncio.to_thread` — no synchronous
network I/O ever runs on the event loop (async-patterns gate; design_questions §2, risks
§blocking client libs). The backend is metadata-only: it lists/``stat``s the share tree and
reports usage from the tree-connect. It inherits the two hard remote invariants from
:class:`~fathom.backends.remote._RemoteBackendBase`:

* :meth:`open_for_hash` raises :class:`~fathom.backends.base.FullBitUnsupportedError` — full-bit
  content hashing never runs over SMB (ADD 02 line 63);
* :meth:`is_busy` is ``False`` (no local backing array to resilver).

SMB session signing/encryption defaults follow the client; credentials come only from the
pluggable secret backend (ADR-010) via a ``secret_provider`` — never code or config — and are
logged count-only. The transport is injectable (a
:class:`~fathom.backends.remote.RemoteTransport`) so the walk/mapping logic is unit-tested
against a fake without a live SMB server (the lazy-imported :mod:`smbprotocol` transport).
"""

from __future__ import annotations

import asyncio
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

_log = get_logger("fathom.backends.smb")

_DEFAULT_SMB_PORT = 445


class SmbBackend(_RemoteBackendBase):
    """A metadata-only :class:`~fathom.backends.base.StorageBackend` over SMB (structural)."""

    protocol = "smb"

    def __init__(
        self,
        config: RemoteBackendConfig,
        *,
        secret_provider: SecretProvider | None = None,
        transport: RemoteTransport | None = None,
    ) -> None:
        if config.protocol != "smb":
            raise ValueError(f"SmbBackend requires protocol='smb', got {config.protocol!r}")
        if not config.share:
            raise ValueError("SmbBackend requires a share name on the config")
        self._config = config
        self._secret_provider = secret_provider
        self._injected_transport = transport
        self._transport: RemoteTransport | None = transport

    def supports(self, mountpoint: str) -> bool:
        """True when this backend's configured target matches ``mountpoint`` (the mount key)."""
        return mountpoint == self._config.mount_key

    def _creds(self) -> RemoteCreds:
        """Resolve SMB creds from the secret backend (ADR-010); count-only logging."""
        creds = resolve_creds(
            username=self._config.username,
            password_ref=self._config.password_ref,
            private_key_ref=None,  # SMB uses user/password, not a key
            secret_provider=self._secret_provider,
        )
        _log.info(
            "resolved smb credentials",
            extra={
                "host": self._config.host,
                "share": self._config.share,
                "has_password": creds.has_password,
            },
        )
        return creds

    async def _ensure_transport(self) -> RemoteTransport:
        if self._transport is not None:
            return self._transport
        creds = self._creds()
        self._transport = await _connect_smbprotocol(self._config, creds)
        return self._transport

    async def volume_info(self, mountpoint: str) -> VolumeInfo:
        """Report share capacity from the tree-connect; ``transport='network'`` (ADD 02)."""
        transport = await self._ensure_transport()
        total, used, free = await transport.statvfs(self._config.remote_path)
        share = self._config.share or ""
        return VolumeInfo(
            # Synthetic POSIX-absolute mountpoint (ADR-029); pretty smb://… as the display label.
            mountpoint=self._config.catalogue_mount,
            display_name=self._config.mount_key,
            fs_type="smb",
            total=total,
            used=used,
            free=free,
            device=f"//{self._config.host}/{share}",
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
        """Metadata-only recursive ``stat`` walk over SMB (never reads file contents).

        ``one_filesystem`` is meaningless across a share and accepted only for protocol parity.
        ``exclude`` (ADR-034) is local-FS subtree pruning; it is accepted for protocol parity but
        not applied to remote shares in this phase.
        The walk is delegated to the shared :func:`~fathom.backends.remote.remote_walk` so SMB and
        SFTP descend identically; the underlying transport offloads every blocking call to a thread.
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
        """Release the SMB session if this backend opened it (idempotent)."""
        if self._transport is not None and self._transport is not self._injected_transport:
            await self._transport.close()
            self._transport = None


async def _connect_smbprotocol(
    config: RemoteBackendConfig, creds: RemoteCreds
) -> RemoteTransport:  # pragma: no cover - requires a live SMB server + optional dep
    """Register a real :mod:`smbprotocol` session (lazy-imported; base runtime dep).

    The blocking ``smbclient.register_session`` is offloaded to a thread. Encryption follows the
    client/server negotiation; credentials are passed from the resolved creds and never logged.
    Raises :class:`MissingClientLibraryError` if :mod:`smbprotocol` is not installed.
    """
    try:
        import smbclient
    except ImportError as exc:  # the optional transport is not installed
        raise MissingClientLibraryError(
            "smbprotocol is required for the SMB backend but is not importable"
        ) from exc

    try:
        await asyncio.to_thread(
            smbclient.register_session,
            config.host,
            username=creds.username,
            password=creds.password,
            port=config.port or _DEFAULT_SMB_PORT,
        )
    except Exception as exc:  # smbprotocol raises a broad hierarchy; normalise to our error
        raise RemoteBackendError(f"smb connection to {config.host!r} failed: {exc}") from exc
    return _SmbProtocolTransport(config, smbclient)


class _SmbProtocolTransport:  # pragma: no cover - thin adapter over the live smbclient module
    r"""Adapts the live blocking :mod:`smbclient` to the async :class:`RemoteTransport` Protocol.

    Every ``smbclient`` call is blocking and so is dispatched via :func:`asyncio.to_thread`.
    Paths are rendered in the ``\\host\share\path`` UNC form smbclient expects.
    """

    def __init__(self, config: RemoteBackendConfig, smbclient_mod: object) -> None:
        self._config = config
        self._smb = smbclient_mod

    def _unc(self, path: str) -> str:
        share = self._config.share or ""
        rel = path.lstrip("/").replace("/", "\\")
        return rf"\\{self._config.host}\{share}\{rel}" if rel else rf"\\{self._config.host}\{share}"

    async def listdir(self, path: str) -> list[RemoteStat]:
        unc = self._unc(path)
        names: list[str] = await asyncio.to_thread(self._smb.listdir, unc)  # type: ignore[attr-defined]
        out: list[RemoteStat] = []
        for name in names:
            child_unc = unc.rstrip("\\") + "\\" + name
            info = await asyncio.to_thread(self._smb.stat, child_unc)  # type: ignore[attr-defined]
            mode = getattr(info, "st_mode", 0)
            child_path = path.rstrip("/") + "/" + name
            out.append(
                _LiveStat(
                    name=name,
                    path=child_path,
                    is_dir=stat_mod.S_ISDIR(mode),
                    is_symlink=stat_mod.S_ISLNK(mode),
                    size=int(getattr(info, "st_size", 0)),
                    mtime=float(getattr(info, "st_mtime", 0.0)),
                    uid=int(getattr(info, "st_uid", 0)),
                    gid=int(getattr(info, "st_gid", 0)),
                )
            )
        return out

    async def statvfs(self, path: str) -> tuple[int, int, int]:
        info = await asyncio.to_thread(self._smb.statvfs, self._unc(path))  # type: ignore[attr-defined]
        total = info.f_blocks * info.f_frsize
        free = info.f_bavail * info.f_frsize
        used = (info.f_blocks - info.f_bfree) * info.f_frsize
        return total, used, free

    async def close(self) -> None:
        await asyncio.to_thread(self._smb.delete_session, self._config.host)  # type: ignore[attr-defined]


class _LiveStat:  # pragma: no cover - simple value carrier for the live transport
    """A concrete :class:`~fathom.backends.remote.RemoteStat` built from live SMB stat info."""

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
