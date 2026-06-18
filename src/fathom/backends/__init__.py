"""StorageBackend implementations (ADR-004, ADD 02 §"StorageBackend interface").

New filesystem or transport support is a plugin implementing one ``Protocol`` — no changes to
the walker, throttler, or push pipeline. The package ships the protocol, the shared Pydantic
frames, the generic read-only POSIX backend, and the specialised plugins:

* :class:`~fathom.backends.zfs.ZfsBackend` — logical-vs-allocated size, ``.zfs/snapshot`` skip,
  dataset boundaries, adapter-sourced topology / resilver state (ADD 04).
* :class:`~fathom.backends.ntfs.NtfsExfatBackend` — NTFS ADS/compression flags; FAT/exFAT
  synthetic ownership (AR-027), for NTFS/exFAT *mounted on Linux* (no native Windows agent).
* :class:`~fathom.backends.smb.SmbBackend` / :class:`~fathom.backends.sftp.SftpBackend` —
  metadata-only remote walks; full-bit hashing is a hard refusal (ADD 02 line 63).

:func:`~fathom.backends.registry.build_default_registry` wires them ahead of the POSIX fallback
(first-match-wins), so the runner resolves the most filesystem-aware plugin per scope.
"""

from fathom.backends.base import (
    FLAG_KEYS,
    SYNTHETIC_GID,
    SYNTHETIC_UID,
    AsyncReader,
    FsEntry,
    FullBitUnsupportedError,
    StorageBackend,
    VolumeInfo,
)
from fathom.backends.ntfs import NtfsExfatBackend
from fathom.backends.posix import PosixBackend
from fathom.backends.registry import BackendRegistry, NoBackendError, build_default_registry
from fathom.backends.remote import (
    MissingClientLibraryError,
    RemoteBackendError,
    RemoteCreds,
    SecretProvider,
    docker_secret_provider,
    env_or_docker_secret_provider,
)
from fathom.backends.sftp import SftpBackend
from fathom.backends.smb import SmbBackend
from fathom.backends.zfs import ZfsBackend

__all__ = [
    "FLAG_KEYS",
    "SYNTHETIC_GID",
    "SYNTHETIC_UID",
    "AsyncReader",
    "BackendRegistry",
    "FsEntry",
    "FullBitUnsupportedError",
    "MissingClientLibraryError",
    "NoBackendError",
    "NtfsExfatBackend",
    "PosixBackend",
    "RemoteBackendError",
    "RemoteCreds",
    "SecretProvider",
    "SftpBackend",
    "SmbBackend",
    "StorageBackend",
    "VolumeInfo",
    "ZfsBackend",
    "build_default_registry",
    "docker_secret_provider",
    "env_or_docker_secret_provider",
]
