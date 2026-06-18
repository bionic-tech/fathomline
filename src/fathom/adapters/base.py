"""The ``PlatformAdapter`` protocol and its control-plane data frames (ADD 04, ADR-008).

A *platform adapter* is the read-only **control-plane** source of truth for a host: pools,
disks, datasets, usage, SMART health, RAID/vdev topology, and — load-bearing — the
resilver/rebuild state that gates full-bit scans (ADD 02 §throttle, ADD 16 hard rule). It
sits **beside** the :class:`~fathom.backends.base.StorageBackend` data plane, which walks
the filesystem; the adapter supplies the *map*, the walk reads the *territory* (ADD 04).

Structural typing (``typing.Protocol``, ``runtime_checkable``) is used per code-quality #9 —
a class is a valid adapter if it has the right shape, no inheritance required — mirroring the
backend protocol exactly.

Safety boundary (ADR-008, ADD 04 "Safety stays in core", STRIDE T-4/E-5): adapters expose
**only** query/read methods and are **never** reachable from the remediation/write path. This
module declares zero write surface and the remediation package never imports
:mod:`fathom.adapters`.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

# Capability literals an adapter may advertise in its manifest ``provides`` set (ADD 04).
# A capability-honest UI renders only what the manifest claims (no faked SMART/usage).
Capability = Literal["pools", "disks", "datasets", "smart", "usage", "topology"]

# Physical transport classes, kept in lock-step with ``backends.VolumeInfo.transport`` so the
# catalogue columns the adapter populates use one vocabulary (ADD 04 "How this threads in").
Transport = Literal["nvme", "sata", "sas", "usb", "unknown"]


class AdapterError(RuntimeError):
    """Base class for every adapter-layer failure (fail-closed, ADD 04 Testing Strategy).

    Callers catch this (or a subclass) and fall back cleanly to a less-capable adapter;
    they never let an adapter failure crash the agent and never silently degrade onto an
    insecure path.
    """


class AdapterUnavailableError(AdapterError):
    """The control-plane endpoint is unreachable or not responding (clean fallback signal).

    Raised on connect/transport failure so the registry can fall back to a CLI/sysfs adapter
    (e.g. :class:`~fathom.adapters.generic_linux.GenericLinuxAdapter`) rather than aborting.
    """


class AdapterAuthError(AdapterError):
    """Authentication/authorization failed — revoked or expired key (fail-closed, STRIDE I-2).

    Distinct from :class:`AdapterUnavailableError`: an auth failure must **never** trigger an
    insecure retry or a downgrade; it surfaces so an operator can rotate the key (ADR-010).
    """


class DiskInfo(BaseModel):
    """One physical disk as reported by the control plane (ADD 04 sketch, verbatim shape).

    ``pool_or_array`` ties the disk to the pool/vdev/md-array it backs, ``None`` when free or
    a spare. ``smart_status`` is ``None`` when the platform cannot report it — the manifest's
    ``provides`` set says whether SMART is trustworthy at all (capability-honest, ADD 04).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    transport: Transport
    size: int = Field(ge=0)
    rotational: bool
    smart_status: str | None = None
    pool_or_array: str | None = None


class PoolInfo(BaseModel):
    """A storage pool / md array / vendor storage pool (ADD 04 sketch, verbatim shape).

    ``resyncing`` is the resilver/rebuild-in-progress flag that drives the full-bit scan guard
    (ADD 02, ADD 16): when any pool a scan touches is resyncing, full-bit hashing is blocked.
    A pool can be **degraded but not resyncing** (a failed member with no rebuild yet) — the
    two states are distinct and modelled separately so the guard does not over- or under-fire.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    raid_level: str | None = None  # mirror | raidz1/2/3 | draid1 | raid5 | ...
    members: list[str] = Field(default_factory=list)
    resyncing: bool = False
    total: int = Field(default=0, ge=0)
    used: int = Field(default=0, ge=0)
    free: int = Field(default=0, ge=0)


class CapabilityManifest(BaseModel):
    """What an adapter can actually tell us about a host (ADD 04, extended with ``api_version``).

    Recorded at onboarding so the rest of the system knows whether to trust the API for
    topology/usage/SMART or fall back per-capability. ``api_version`` records the version the
    middleware **negotiated** (e.g. ``"v25.10"``) so version drift is observable, not silent
    (ADD 04 "the manifest records which version answered").
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: str  # truenas | synology | qnap | unraid | generic-linux | generic-windows
    api_available: bool
    provides: frozenset[Capability] = Field(default_factory=frozenset)
    api_version: str | None = None


@runtime_checkable
class PlatformAdapter(Protocol):
    """Control-plane source of truth for a host — API-backed where possible (ADD 04, verbatim).

    Every method is read-only. Any class implementing this shape is a valid adapter
    (structural typing); the conformance suite in ``tests/adapters/test_conformance.py`` is
    the contract every adapter — core or community — must pass.
    """

    async def probe(self) -> CapabilityManifest:
        """Connect (if needed) and report what this adapter can supply for the host."""
        ...

    async def list_pools(self) -> list[PoolInfo]:
        """Return every storage pool / array with its topology and resync state."""
        ...

    async def list_disks(self) -> list[DiskInfo]:
        """Return every physical disk with transport, size, and (where available) SMART."""
        ...

    async def volume_usage(self, mountpoint: str) -> tuple[int, int, int]:
        """Return ``(total, used, free)`` bytes for the volume backing ``mountpoint``."""
        ...

    async def is_array_healthy(self, pool: str) -> bool:
        """Return ``False`` while ``pool`` is resilvering/rebuilding (gates full-bit, ADD 02)."""
        ...

    async def close(self) -> None:
        """Release the persistent session/connection (idempotent)."""
        ...
