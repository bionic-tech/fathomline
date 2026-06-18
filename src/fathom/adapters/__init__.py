"""PlatformAdapter implementations — read-only host control plane (ADD 04, ADR-008).

The control-plane layer that sits beside the :mod:`fathom.backends` data plane: a host's
authoritative source for pools, disks, datasets, usage, SMART, topology, and the resilver
state that gates full-bit scans (ADD 02, ADD 16). Adapters are API-first with a CLI/sysfs
fallback, never on the write path, and hold no more privilege than reading topology/usage
requires (AR-0011, STRIDE T-4/E-5). TrueNAS (JSON-RPC 2.0 WebSocket) + a generic Linux
adapter ship first; other NAS vendors are P1/community plugins behind the same Protocol.

The TrueNAS WebSocket transport libraries are an optional dependency (extra ``truenas``);
the Protocol, frames, registry, config, and the generic adapter are dependency-free, so
importing this package without the extra always works (the transport is lazily imported).
"""

from fathom.adapters.base import (
    AdapterAuthError,
    AdapterError,
    AdapterUnavailableError,
    Capability,
    CapabilityManifest,
    DiskInfo,
    PlatformAdapter,
    PoolInfo,
    Transport,
)
from fathom.adapters.config import AdapterConfig, SsrfError, assert_endpoint_allowed
from fathom.adapters.discovery import (
    AdapterSpec,
    PlatformClass,
    ProbeSignals,
    suggest_platform,
)
from fathom.adapters.generic_linux import GenericLinuxAdapter
from fathom.adapters.jsonrpc import JsonRpcClient, JsonRpcTransport
from fathom.adapters.registry import AdapterRegistry, NoAdapterError
from fathom.adapters.resync import adapter_resync_provider
from fathom.adapters.truenas import TrueNASAdapter

__all__ = [
    "AdapterAuthError",
    "AdapterConfig",
    "AdapterError",
    "AdapterRegistry",
    "AdapterSpec",
    "AdapterUnavailableError",
    "Capability",
    "CapabilityManifest",
    "DiskInfo",
    "GenericLinuxAdapter",
    "JsonRpcClient",
    "JsonRpcTransport",
    "NoAdapterError",
    "PlatformAdapter",
    "PlatformClass",
    "PoolInfo",
    "ProbeSignals",
    "SsrfError",
    "Transport",
    "TrueNASAdapter",
    "adapter_resync_provider",
    "assert_endpoint_allowed",
    "suggest_platform",
]
