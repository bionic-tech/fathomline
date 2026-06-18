"""rclone storage backend — metadata walk over any rclone remote (ADR-004, ADR-028).

[rclone](https://rclone.org) speaks ~70 cloud/object backends (Google Drive, S3, Dropbox,
OneDrive, Backblaze B2, …). This backend shells out to the ``rclone`` binary to enumerate a
configured remote as a metadata-only stream — so a cloud drive shows up in Fathomline's estate
view (sizes, treemap, largest, search, growth) exactly like a local volume, **with no file
contents downloaded** (no egress beyond the listing API call).

It inherits the remote invariants from :class:`~fathom.backends.remote._RemoteBackendBase`:

* :meth:`open_for_hash` raises :class:`~fathom.backends.base.FullBitUnsupportedError` — content
  hashing never runs over rclone (the agent would have to download the file; ADD 02 line 63);
* :meth:`is_busy` is ``False`` (no local backing array).

Auth is **not** Fathomline's concern: the remote's credentials live in the host's ``rclone.conf``
(configured out of band), so the agent config carries only the remote *name* (``host``) and a
subpath (``remote_path``) — never a secret. The ``rclone`` invocation uses
``create_subprocess_exec`` (argument vector, **no shell**), so a config value cannot inject a
command. The runner is injectable so the walk/mapping logic is unit-tested against canned
``lsjson`` output without a real rclone binary or network.

Provider-side content hashes (``rclone lsjson --hash`` returns MD5/SHA-1/QuickXorHash that the
provider already computed) would enable *zero-egress* cross-cloud duplicate detection; that needs
a catalogue column and a dedup path keyed on provider-hash type, designed in ADR-028 and deferred.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Collection
from dataclasses import dataclass
from datetime import datetime

from fathom.agent.config import RemoteBackendConfig
from fathom.backends.base import SYNTHETIC_GID, SYNTHETIC_UID, FsEntry, VolumeInfo
from fathom.backends.remote import (
    MissingClientLibraryError,
    RemoteBackendError,
    _RemoteBackendBase,
    synthetic_inode,
)
from fathom.logging import get_logger

_log = get_logger("fathom.backends.rclone")

_DEFAULT_RCLONE = "rclone"
# A hung `rclone` listing must not block the agent forever; matches the codebase's wait_for pattern.
_DEFAULT_TIMEOUT = 600.0
# Bound the listing buffer: `lsjson --recursive` emits one JSON array, so a huge remote would
# otherwise materialize unboundedly in memory (the local walk holds a 50M-entry bounded contract;
# a streaming lsf reader is the ADR-028 phase-2 fix). Past this we fail LOUD, not OOM.
_MAX_OUTPUT_BYTES = 256 * 1024 * 1024
_MAX_STDERR_BYTES = 64 * 1024
# int64 ceiling for a catalogue size column (saturate corrupted/hostile remote sizes).
_MAX_SIZE = 2**63 - 1


# Which provider hash to keep when `lsjson --hash` returns several (ADR-028 phase 2). Fixed
# preference so a remote that exposes multiple algorithms always yields the same (algo, hash) —
# two files on that remote then compare like-with-like. Cross-remote with different algorithms
# simply won't group (correct: an md5 can't be compared to a sha1).
_HASH_PREFERENCE = ("sha256", "sha1", "md5", "quickxorhash", "crc32", "dropbox", "whirlpool")
# Defensive bounds matching the wire/catalogue contract; a hash that doesn't fit is dropped (not
# truncated) so one odd value can never break the agent's push-batch validation.
_PROVIDER_HASH_RE = re.compile(r"^[A-Za-z0-9+/=_-]{1,128}$")
_PROVIDER_ALGO_RE = re.compile(r"^[a-z0-9._-]{1,32}$")


def _pick_provider_hash(hashes: dict[str, object]) -> tuple[str | None, str | None]:
    """Choose one (algo, hash) from rclone's ``Hashes`` map by :data:`_HASH_PREFERENCE`.

    Returns ``(None, None)`` if nothing usable. A value that fails the bounds/charset guard is
    skipped rather than truncated, so a malformed provider hash can never break the push frame.
    """
    for algo in _HASH_PREFERENCE:
        value = hashes.get(algo)
        if (
            isinstance(value, str)
            and _PROVIDER_HASH_RE.match(value)
            and _PROVIDER_ALGO_RE.match(algo)
        ):
            return algo, value
    return None, None


@dataclass(frozen=True, slots=True)
class RcloneEntry:
    """One entry from ``rclone lsjson`` (relative ``path`` within the listed remote root)."""

    path: str
    name: str
    is_dir: bool
    size: int
    mtime: float
    provider_hash: str | None = None
    provider_hash_algo: str | None = None

    @classmethod
    def from_json(cls, obj: dict[str, object]) -> RcloneEntry:
        raw = obj.get("Size", 0)
        # rclone reports -1 for unknown size (some backends, directories) → clamp to 0. Saturate at
        # int64 so corrupted/hostile remote metadata (Size: 1e30) can never overflow the catalogue's
        # BigInteger column or wrap a rollup SUM (defence against untrusted provider output).
        size = min(max(0, raw if isinstance(raw, int) else 0), _MAX_SIZE)
        raw_hashes = obj.get("Hashes")
        algo, value = (
            _pick_provider_hash(raw_hashes) if isinstance(raw_hashes, dict) else (None, None)
        )
        return cls(
            path=str(obj.get("Path", "")),
            name=str(obj.get("Name", "")),
            is_dir=bool(obj.get("IsDir", False)),
            size=size,
            mtime=_parse_modtime(obj.get("ModTime")),
            provider_hash=value,
            provider_hash_algo=algo,
        )


def _parse_modtime(value: object) -> float:
    """Parse an rclone RFC3339 ``ModTime`` to an epoch float; 0.0 if absent/unparseable.

    rclone emits up to nanosecond precision and a trailing ``Z``; Python's ``fromisoformat``
    accepts ``Z`` (3.11+) but only microsecond fractional digits, so trim a longer fraction.
    """
    if not isinstance(value, str) or not value:
        return 0.0
    text = value
    if "." in text:
        head, _, tail = text.partition(".")
        # The fraction is the leading digit-run; everything after it is the tz suffix (Z / +hh:mm).
        i = 0
        while i < len(tail) and tail[i].isdigit():
            i += 1
        frac = tail[:i][:6]  # fromisoformat accepts at most microsecond precision
        suffix = tail[i:]
        text = f"{head}.{frac}{suffix}" if frac else f"{head}{suffix}"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 0.0


class RcloneRunner:
    """The injectable seam: the reads a metadata walk performs against an rclone remote.

    The live implementation shells out to the ``rclone`` binary; tests inject a fake returning
    canned ``lsjson`` output. (A plain class, not a ``Protocol``, so the live subprocess runner is
    the default and fakes simply subclass or duck-type the two coroutines.)
    """

    async def lsjson(self, remote: str) -> list[RcloneEntry]:  # pragma: no cover - overridden
        raise NotImplementedError

    async def about(self, remote: str) -> tuple[int, int, int]:  # pragma: no cover - overridden
        raise NotImplementedError


class RcloneBackend(_RemoteBackendBase):
    """A metadata-only :class:`~fathom.backends.base.StorageBackend` over an rclone remote."""

    protocol = "rclone"

    def __init__(
        self,
        config: RemoteBackendConfig,
        *,
        runner: RcloneRunner | None = None,
        rclone_path: str = _DEFAULT_RCLONE,
    ) -> None:
        if config.protocol != "rclone":
            raise ValueError(f"RcloneBackend requires protocol='rclone', got {config.protocol!r}")
        self._config = config
        self._runner = runner or _SubprocessRcloneRunner(rclone_path)

    def supports(self, mountpoint: str) -> bool:
        """True when this backend's configured remote matches ``mountpoint`` (the mount key)."""
        return mountpoint == self._config.mount_key

    def _remote(self) -> str:
        """Compose the ``<remote>:<subpath>`` rclone target from the config (no leading dash).

        e.g. host=``gdrive`` + remote_path=``/Backups`` → ``gdrive:Backups``; remote_path=``/`` →
        ``gdrive:`` (the remote root). A leading ``-`` would be misread by rclone as a flag, so a
        composed target that begins with one is refused (defence-in-depth; the host validator
        already rejects scheme/path characters).
        """
        target = f"{self._config.host}:{self._config.remote_path.lstrip('/')}"
        if target.startswith("-"):
            raise RemoteBackendError(f"unsafe rclone remote {target!r} (leading dash)")
        return target

    async def volume_info(self, mountpoint: str) -> VolumeInfo:
        """Report capacity via ``rclone about`` (0 where the backend cannot report it)."""
        total, used, free = await self._runner.about(self._remote())
        return VolumeInfo(
            # Synthetic POSIX-absolute mountpoint (ADR-029) so the catalogue/ingest/read contract
            # holds; the pretty rclone://… rides along as the display_name.
            mountpoint=self._config.catalogue_mount,
            display_name=self._config.mount_key,
            fs_type="rclone",
            total=total,
            used=used,
            free=free,
            device=self._remote(),
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
        """Metadata-only walk via ``rclone lsjson --recursive`` (never downloads contents).

        ``follow_symlinks`` / ``one_filesystem`` are meaningless for a cloud remote and accepted
        only for protocol parity. Entry paths are anchored under the synthetic ``catalogue_mount``
        (e.g. ``/rclone/gdrive/Backups/sub/file``) so they satisfy the catalogue path contract
        (ADR-029); ownership is synthetic (cloud objects have no POSIX uid/gid — AR-027).
        ``exclude`` (ADR-034) is local-FS subtree pruning; accepted for parity, not applied here.
        """
        base = self._config.catalogue_mount
        for entry in await self._runner.lsjson(self._remote()):
            rel = entry.path.lstrip("/")
            full = f"{base}/{rel}" if rel else (base or "/")
            yield FsEntry(
                path=full,
                name=entry.name,
                is_dir=entry.is_dir,
                is_symlink=False,
                size_logical=entry.size,
                size_on_disk=entry.size,  # no allocation info over a remote (capability-honest)
                mtime=entry.mtime,
                ctime=entry.mtime,
                uid=SYNTHETIC_UID,
                gid=SYNTHETIC_GID,
                # Stable per-path synthetic inode so cloud entries don't collide on (host,vol,0,0).
                inode=synthetic_inode(full),
                flags={"synthetic_owner": True},
                # Provider-attested hash (no download); report-only dedup signal (ADR-028 phase 2).
                provider_hash=entry.provider_hash if not entry.is_dir else None,
                provider_hash_algo=entry.provider_hash_algo if not entry.is_dir else None,
            )


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    """Best-effort kill of a timed-out / over-cap rclone process (never raises)."""
    try:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
    except ProcessLookupError:  # pragma: no cover - already gone
        pass


class _SubprocessRcloneRunner(RcloneRunner):
    """Drives the real ``rclone`` binary via ``create_subprocess_exec`` (no shell).

    Two robustness bounds (Win/rclone adversarial review): a wall-clock ``timeout`` so a hung
    listing can never block the agent forever, and ``max_output_bytes`` so a very large remote's
    listing fails LOUD at a ceiling instead of OOM-ing (stdout is read incrementally with an
    early abort; stderr is drained concurrently and bounded so the child can never deadlock on a
    full stderr pipe). Both are constructor params for testability.
    """

    def __init__(
        self,
        rclone_path: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_output_bytes: int = _MAX_OUTPUT_BYTES,
    ) -> None:
        self._rclone = rclone_path
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes

    async def _run(self, *args: str) -> bytes:
        try:
            proc = await asyncio.create_subprocess_exec(
                self._rclone,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise MissingClientLibraryError(
                f"the rclone binary ({self._rclone!r}) is required for the rclone backend "
                "but was not found on PATH"
            ) from exc
        try:
            out, over, err = await asyncio.wait_for(self._drain(proc), timeout=self._timeout)
        except TimeoutError as exc:
            await _terminate(proc)
            raise RemoteBackendError(
                f"rclone {args[0]} timed out after {self._timeout:.0f}s"
            ) from exc
        if over:
            await _terminate(proc)
            raise RemoteBackendError(
                f"rclone {args[0]} output exceeded {self._max_output_bytes} bytes — remote too "
                "large for the single-shot lister (ADR-028 phase-2 streaming reader is the fix)"
            )
        returncode = await proc.wait()
        if returncode != 0:
            detail = err.decode("utf-8", "replace").strip()[:400]
            raise RemoteBackendError(f"rclone {args[0]} failed (exit {returncode}): {detail}")
        return out

    async def _drain(self, proc: asyncio.subprocess.Process) -> tuple[bytes, bool, bytes]:
        """Read stdout (capped, early-abort) and stderr (bounded) concurrently; no pipe deadlock."""
        stdout, stderr = proc.stdout, proc.stderr
        if stdout is None or stderr is None:  # pragma: no cover - we always pass PIPE
            raise RemoteBackendError("rclone subprocess stdio pipes are unavailable")

        async def read_stderr() -> bytes:
            buf = bytearray()
            while True:
                chunk = await stderr.read(8192)
                if not chunk:
                    return bytes(buf)
                if len(buf) < _MAX_STDERR_BYTES:
                    buf.extend(chunk[: _MAX_STDERR_BYTES - len(buf)])

        err_task = asyncio.create_task(read_stderr())
        out = bytearray()
        over = False
        while True:
            chunk = await stdout.read(65536)
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > self._max_output_bytes:
                over = True
                break
        if over:
            err_task.cancel()
            err = b""
        else:
            err = await err_task
        return bytes(out), over, err

    async def lsjson(self, remote: str) -> list[RcloneEntry]:
        # --hash asks rclone for the provider's precomputed content hashes (no download); they
        # feed report-only cross-cloud duplicate detection (ADR-028 phase 2).
        out = await self._run("lsjson", "--recursive", "--hash", remote)
        try:
            data = json.loads(out or b"[]")
        except json.JSONDecodeError as exc:
            raise RemoteBackendError(f"rclone lsjson returned invalid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise RemoteBackendError("rclone lsjson did not return a JSON array")
        return [RcloneEntry.from_json(obj) for obj in data if isinstance(obj, dict)]

    async def about(self, remote: str) -> tuple[int, int, int]:
        # `rclone about` needs only the remote root, not the subpath.
        root = remote.split(":", 1)[0] + ":"
        out = await self._run("about", "--json", root)
        try:
            data = json.loads(out or b"{}")
        except json.JSONDecodeError:
            return 0, 0, 0
        if not isinstance(data, dict):  # a non-object JSON value (null/array/string) → unknown
            return 0, 0, 0
        total = int(data.get("total", 0) or 0)
        used = int(data.get("used", 0) or 0)
        free = int(data.get("free", 0) or 0)
        return total, used, free
