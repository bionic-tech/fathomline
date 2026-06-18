"""Shared remote-backend base for SMB/SFTP (ADR-004, ADD 02 §Mode 2, ADR-010).

The SMB and SFTP backends share three load-bearing rules, all enforced here so neither plugin
can drift from them:

1. **Metadata-only.** A remote walk is ``stat``-equivalent over the protocol; it never reads
   file contents. :meth:`_RemoteBackendBase.open_for_hash` *raises*
   :class:`~fathom.backends.base.FullBitUnsupportedError` — full-bit hashing is forbidden over
   SFTP/SMB/NFS (ADD 02 line 63, security_constraints). The refusal is a hard error, not a
   config toggle, so it is regression-tested and cannot be flipped on.
2. **Change feed = periodic re-stat by mtime.** Remote protocols have no ``fanotify``/USN/
   ``zfs diff`` feed (ADD 02 table line 145), so the only light-touch incremental signal is to
   re-``stat`` a directory and compare mtimes. :func:`restat_changed` is that primitive, shared
   so both backends throttle identically.
3. **Credentials by reference only.** SMB/SSH creds come *only* from the pluggable secret
   backend (ADR-010) via a ``secret_provider`` seam — never from code, ``.env``, or the config
   object. :class:`RemoteCreds` carries the resolved material for the lifetime of one
   connection; logging is count-only (``has_password`` / ``has_key``, never the value).

There is **no local backing array** behind a remote share, so :meth:`is_busy` is always
``False`` — the resync guard is a property of the host that *owns* the data, which (per ADD 02)
is the only place full-bit ever runs anyway.

``verify_ssl`` / host-key verification is **on by default**; the insecure escape hatch
(:class:`~fathom.agent.config.RemoteBackendConfig.lab_insecure`) is loud and lab-only, parity
with the adapter SSRF rule and code-quality #6.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import AsyncIterator, Callable, Iterable
from pathlib import Path
from typing import Protocol, runtime_checkable

from fathom.backends.base import FsEntry, FullBitUnsupportedError
from fathom.logging import get_logger

_log = get_logger("fathom.backends.remote")

# A "resolve this secret reference to its material" seam (ADR-010). The same shape the TrueNAS
# adapter uses for ``api_key_ref`` — one canonical secret-resolution signature across the agent.
SecretProvider = Callable[[str], str]

# Directory Docker mounts secrets into (ADR-010 "Docker secrets" backend). A minimal resolver;
# OpenBao is the documented production option and is deferred to the full secret subsystem.
_DOCKER_SECRETS_DIR = Path("/run/secrets")


class RemoteBackendError(RuntimeError):
    """A remote backend could not be constructed or connected (fail-closed).

    Distinct from :class:`~fathom.backends.base.FullBitUnsupportedError` (a deliberate refusal):
    this signals a *failure* — a missing client library, an unresolved credential, or a
    transport error — so the caller can skip the target cleanly rather than crash the run.
    """


class MissingClientLibraryError(RemoteBackendError):
    """A remote backend's transport library (asyncssh / smbprotocol) is not importable.

    The transports are base runtime deps but are lazy-imported (per the :mod:`fathom.adapters._ws`
    precedent) so the package still imports if a stripped-down deploy removed them; connecting then
    raises this with an actionable message rather than failing obscurely at import time.
    """


class RemoteCreds:
    """Resolved credential material for one remote connection (held in memory, never logged).

    Built from a :class:`~fathom.agent.config.RemoteBackendConfig`'s *references* via a
    ``secret_provider`` (ADR-010). ``__repr__`` is redacted so an accidental log/traceback never
    leaks a secret (count-only logging, sec-arch §6).
    """

    __slots__ = ("_password", "_private_key", "username")

    def __init__(
        self,
        *,
        username: str | None = None,
        password: str | None = None,
        private_key: str | None = None,
    ) -> None:
        self.username = username
        self._password = password
        self._private_key = private_key

    @property
    def password(self) -> str | None:
        return self._password

    @property
    def private_key(self) -> str | None:
        return self._private_key

    @property
    def has_password(self) -> bool:
        return self._password is not None

    @property
    def has_key(self) -> bool:
        return self._private_key is not None

    def __repr__(self) -> str:  # pragma: no cover - trivial, but must stay redacted
        return (
            f"RemoteCreds(username={self.username!r}, "
            f"has_password={self.has_password}, has_key={self.has_key})"
        )


def docker_secret_provider(ref: str) -> str:
    """Resolve a secret *reference* to its material from the Docker-secrets mount (ADR-010).

    Reads ``/run/secrets/<ref>`` — the path Docker/Compose mounts a named secret to. The value
    is stripped of a single trailing newline (the common ``echo "secret" | docker secret create``
    artefact) but otherwise returned verbatim. The reference (a filename, not the secret) may be
    logged; the resolved value never is.

    Raises:
        RemoteBackendError: If the named secret is not present in the secrets mount.
    """
    if "/" in ref or ref in {"", ".", ".."}:
        raise RemoteBackendError(f"invalid secret reference {ref!r} (must be a bare secret name)")
    path = _DOCKER_SECRETS_DIR / ref
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RemoteBackendError(
            f"secret {ref!r} not found in the Docker-secrets mount (ADR-010)"
        ) from exc
    _log.info("resolved remote credential from secret backend", extra={"secret_ref": ref})
    return raw.rstrip("\n")


def resolve_creds(
    *,
    username: str | None,
    password_ref: str | None,
    private_key_ref: str | None,
    secret_provider: SecretProvider | None,
) -> RemoteCreds:
    """Resolve credential *references* to :class:`RemoteCreds` via the secret backend (ADR-010).

    The *secret* references — ``password_ref`` and ``private_key_ref`` — are passed through
    ``secret_provider``; a secret reference with no provider is a fail-closed error (creds must
    come from the secret backend, never inline). The ``username`` is **not** a secret (it is an
    identity), so it is carried verbatim and never sent through the provider.

    Raises:
        RemoteBackendError: If a secret reference is set but no ``secret_provider`` is supplied.
    """
    if (password_ref is not None or private_key_ref is not None) and secret_provider is None:
        raise RemoteBackendError(
            "a credential reference is set but no secret_provider was supplied to resolve it "
            "(ADR-010: creds come only from the pluggable secret backend)"
        )
    password = secret_provider(password_ref) if password_ref and secret_provider else None
    private_key = secret_provider(private_key_ref) if private_key_ref and secret_provider else None
    return RemoteCreds(username=username, password=password, private_key=private_key)


def restat_changed(
    previous: dict[str, float],
    current: Iterable[tuple[str, float]],
) -> set[str]:
    """Return the set of paths whose mtime changed (the remote re-stat change feed primitive).

    The remote change feed is, by necessity, a periodic re-``stat`` comparing each path's mtime
    to the prior cycle (ADD 02 line 145 — no native feed over SMB/SFTP). A path is *changed* if
    it is new or its mtime differs from ``previous``. This is the only incremental signal the
    remote backends expose; it is intentionally O(paths-restatted) and so must be throttled by
    the supervisor's scan window like any other walk (risks §remote re-stat).
    """
    changed: set[str] = set()
    for path, mtime in current:
        prior = previous.get(path)
        if prior is None or prior != mtime:
            changed.add(path)
    return changed


@runtime_checkable
class RemoteStat(Protocol):
    """The subset of a remote ``stat`` result a metadata walk needs (transport-agnostic).

    Shared by the SMB and SFTP transports so the walk + entry mapping is written once. A remote
    protocol exposes no ``st_blocks`` and no stable inode, reflected in :func:`to_fs_entry`.
    """

    @property
    def name(self) -> str: ...
    @property
    def path(self) -> str: ...
    @property
    def is_dir(self) -> bool: ...
    @property
    def is_symlink(self) -> bool: ...
    @property
    def size(self) -> int: ...
    @property
    def mtime(self) -> float: ...
    @property
    def uid(self) -> int: ...
    @property
    def gid(self) -> int: ...


@runtime_checkable
class RemoteTransport(Protocol):
    """An opened remote session reduced to the reads a metadata walk performs (injectable).

    Both the SMB and SFTP backends drive this shape; the concrete transports lazy-import their
    client library, and tests inject a fake so the walk/mapping logic runs without a live server.
    """

    async def listdir(self, path: str) -> list[RemoteStat]:
        """Return one directory's children as remote stat frames (no content read)."""
        ...

    async def statvfs(self, path: str) -> tuple[int, int, int]:
        """Return ``(total, used, free)`` bytes for the share/path."""
        ...

    async def close(self) -> None:
        """Release the remote session (idempotent)."""
        ...


def synthetic_inode(path: str) -> int:
    """A stable, per-path 64-bit pseudo-inode for backends with no real inode (remote/cloud).

    The catalogue identity is ``(host_id, volume_id, dev, inode)``. Remote/cloud entries have no
    inode, so without this they would all share ``inode=0`` and collide on the upsert key —
    clobbering each other so only one entry per volume survives (ADR-029). Deriving the inode from
    the (catalogue) path makes it **stable across scans** (so re-scans upsert, not duplicate) and
    unique per path. 64-bit BLAKE2b; collision risk is negligible at homelab estate scale. This is
    the same approach rclone's own VFS uses to invent inodes. ``dev`` stays 0 for remote volumes.
    """
    digest = hashlib.blake2b(path.encode("utf-8", "surrogatepass"), digest_size=8).digest()
    return int.from_bytes(digest, "big") & 0x7FFF_FFFF_FFFF_FFFF


def to_fs_entry(stat: RemoteStat, *, path: str | None = None) -> FsEntry:
    """Map a remote stat frame to an :class:`FsEntry` (size_on_disk == logical over the wire).

    A remote ``stat`` cannot report allocated/on-disk size (no ``st_blocks`` over SMB/SFTP), so
    ``size_on_disk`` equals ``size_logical`` — honest: we report what the protocol tells us and
    never fabricate an allocation figure (capability-honest, AR-027). ``ctime`` mirrors ``mtime``
    (remote protocols expose mtime, not a POSIX ctime), and ``inode`` is a **stable synthetic**
    derived from the path (:func:`synthetic_inode`) so remote entries do not collide on the
    catalogue identity (ADR-029).

    ``path`` overrides the stored path so the walk can anchor entries under the synthetic
    ``catalogue_mount`` (ADR-029) rather than the real remote path; the real path is still used to
    recurse, and is what the synthetic inode is derived from.
    """
    effective_path = path if path is not None else stat.path
    return FsEntry(
        path=effective_path,
        name=stat.name,
        is_dir=stat.is_dir,
        is_symlink=stat.is_symlink,
        size_logical=stat.size,
        size_on_disk=stat.size,
        mtime=stat.mtime,
        ctime=stat.mtime,
        uid=stat.uid,
        gid=stat.gid,
        inode=synthetic_inode(effective_path),
        flags={},
    )


def _to_catalogue_path(real_path: str, *, remote_root: str, mount: str) -> str:
    """Rewrite a real remote path to the synthetic ``catalogue_mount`` namespace (ADR-029).

    ``/data/sub/file`` under remote_root ``/data`` and mount ``/sftp/host/data`` → that mount plus
    the path relative to the root (``/sub/file``). The volume root itself maps to the mount.
    """
    rel = real_path[len(remote_root.rstrip("/")) :]
    return (mount + rel) if rel else mount


async def remote_walk(
    transport: RemoteTransport,
    root: str,
    *,
    follow_symlinks: bool,
    log_component: str,
    mount: str,
    remote_root: str,
) -> AsyncIterator[FsEntry]:
    """Metadata-only iterative ``stat`` walk over a remote transport (never reads contents).

    Shared by both remote backends. Entry paths are rewritten into the synthetic
    ``catalogue_mount`` namespace (``mount``, ADR-029) so they satisfy the catalogue path
    contract, while the real remote path (under ``remote_root``) is used to recurse. Symlinks are
    reported but never traversed unless ``follow_symlinks`` is set; an unreadable directory is
    logged and skipped, so one permission error never aborts the whole share scan (parity with the
    POSIX walk's resilience).
    """
    log = get_logger(log_component)
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = await transport.listdir(current)
        except OSError as exc:
            log.warning("remote dir skipped", extra={"path": current, "error": str(exc)})
            continue
        for child in children:
            cat_path = _to_catalogue_path(child.path, remote_root=remote_root, mount=mount)
            yield to_fs_entry(child, path=cat_path)
            if child.is_dir and (follow_symlinks or not child.is_symlink):
                stack.append(child.path)  # the REAL remote path — used to recurse via listdir


class _RemoteBackendBase:
    """Shared behaviour for metadata-only remote backends (SMB, SFTP).

    Concrete backends supply :meth:`supports`, :meth:`volume_info`, and :meth:`walk`; this base
    pins the two invariants common to *every* remote transport — the full-bit refusal and the
    "no local array" busy state — so a subclass cannot accidentally implement either wrongly.
    """

    # Set by subclasses; surfaced in VolumeInfo and used to scope the full-bit refusal message.
    protocol: str = "remote"

    async def open_for_hash(self, path: str) -> _NeverReader:
        """Refuse content hashing — full-bit never runs over SMB/SFTP/NFS (ADD 02 line 63).

        This raises rather than returning a reader so the prohibition is a hard, regression-tested
        boundary (test_remote::open_for_hash raises). The return annotation is a reader purely to
        satisfy the :class:`~fathom.backends.base.StorageBackend` protocol shape; control never
        reaches a return.
        """
        raise FullBitUnsupportedError(
            f"full-bit content hashing is not permitted over {self.protocol!r} "
            f"(ADD 02 §Mode 2): refusing to open {path!r}"
        )

    async def is_busy(self) -> bool:
        """Always ``False`` — there is no local backing array to resilver behind a remote share.

        The resync guard is a property of the host that *owns* the data; full-bit (the only mode
        the guard gates) never runs over a remote transport anyway, so there is nothing to gate.
        """
        return False


class _NeverReader:  # pragma: no cover - exists only as the unreachable return type
    """Phantom reader type for :meth:`_RemoteBackendBase.open_for_hash`'s signature; never built."""

    async def read(self, size: int) -> bytes:
        raise FullBitUnsupportedError("remote backends never produce a content reader")

    async def seek(self, offset: int) -> int:
        raise FullBitUnsupportedError("remote backends never produce a content reader")

    async def close(self) -> None:
        raise FullBitUnsupportedError("remote backends never produce a content reader")


def env_or_docker_secret_provider(ref: str) -> str:
    """Resolve a secret from an env var first, then the Docker-secrets mount (ADR-010 simple path).

    A convenience provider for deployments that inject creds as environment variables (the
    common Compose pattern) with a Docker-secrets-file fallback. Production should prefer the
    secret backend directly; OpenBao is the documented production option, deferred here.
    """
    value = os.environ.get(ref)
    if value is not None:
        _log.info("resolved remote credential from environment", extra={"secret_ref": ref})
        return value
    return docker_secret_provider(ref)
