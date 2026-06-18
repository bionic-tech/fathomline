"""TrueNAS control-plane adapter over persistent JSON-RPC 2.0 / WebSocket (ADD 04, P0).

The authoritative control plane for an estate's primary data host (e.g. a TrueNAS
SCALE 25.10.1 box, ZFS 136T ``tank`` draid1, *no* ``/proc/mdstat``; AR-0002). TrueNAS's
own middleware is authoritative — direct ``zfs``/``zpool`` parsing is fragile and version-drifts
(ADD 04 D8) — so this adapter prefers the API for pools/disks/datasets/usage/SMART/topology
and, load-bearing, for the **resilver state** that gates full-bit scans (ADD 02, ADD 16).

Design rules encoded (ADD 04):

* ONE persistent authenticated WebSocket per agent lifetime — never a per-call ``midclt``
  shell-out (AR-017 SRE, AR-024 FinOps). Reconnect with tenacity backoff lives in
  :class:`~fathom.adapters.jsonrpc.JsonRpcClient`.
* On-box → local socket, no key needed for the root context; remote → ``wss`` with a
  user-linked, least-privilege, read-only API key (STRIDE I-2). ``verify_ssl=True`` always
  outside the validated lab profile (:class:`~fathom.adapters.config.AdapterConfig`).
* JSON-RPC 2.0 only — the legacy REST API is removed in TrueNAS 26 (ADD 04, AR-001/AR-029).
  The pinned API version is negotiated and recorded in the manifest.
* READ-ONLY: only ``*.query`` / ``pool.status`` / ``reporting`` / SMART reads. Zero write
  surface; never reachable from the remediation path (ADR-008, STRIDE T-4/E-5).

TODO(truenas-live-verify): the exact middleware method names, params, and the version-negotiation
call below are coded defensively from the documented JSON-RPC surface; verify each against a
live TrueNAS box before merge (ADD 04 risk: methods are version-fragile).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from fathom.adapters.base import (
    AdapterUnavailableError,
    Capability,
    CapabilityManifest,
    DiskInfo,
    PoolInfo,
    Transport,
)
from fathom.adapters.config import AdapterConfig
from fathom.adapters.discovery import PlatformClass
from fathom.adapters.jsonrpc import JsonRpcClient, JsonRpcTransport, build_websocket_transport
from fathom.logging import get_logger

_log = get_logger("fathom.adapters.truenas")

# Capabilities the TrueNAS middleware supplies once a session is up (capability-honest UI).
_TRUENAS_PROVIDES: frozenset[Capability] = frozenset(
    {"pools", "disks", "datasets", "smart", "usage", "topology"}
)

# Known transport tokens TrueNAS reports for a disk → our normalised vocabulary (ADD 04).
_TRANSPORT_MAP: dict[str, Transport] = {
    "nvme": "nvme",
    "sata": "sata",
    "sas": "sas",
    "usb": "usb",
}

# ZFS pool states that indicate an in-flight resilver/scrub touching redundancy. A pool can be
# DEGRADED *without* resilvering (a failed member, no rebuild started — the node-0 nextcloud
# evidence in AR-0002 §5); that is unhealthy-but-not-resyncing and must NOT trip the full-bit
# guard, which keys strictly on an active resilver (ADD 02).
_RESILVER_STATES: frozenset[str] = frozenset({"RESILVERING", "RESILVER"})


def _coerce_transport(raw: object) -> Transport:
    if isinstance(raw, str):
        return _TRANSPORT_MAP.get(raw.lower(), "unknown")
    return "unknown"


class TrueNASAdapter:
    """A read-only :class:`~fathom.adapters.base.PlatformAdapter` over TrueNAS middleware.

    The transport is injectable so the JSON-RPC mappers are unit-testable against fixtures
    without a live box (ADD 04 Testing Strategy); in production it is the lazily-imported
    WebSocket transport. ``secret_provider`` resolves the ``api_key_ref`` to key material at
    runtime (ADR-010) — the key is never stored on the config or in code.
    """

    def __init__(
        self,
        config: AdapterConfig,
        *,
        secret_provider: Callable[[str], str] | None = None,
        transport: JsonRpcTransport | None = None,
    ) -> None:
        if config.platform is not PlatformClass.TRUENAS:
            raise ValueError(f"TrueNASAdapter requires platform=truenas, got {config.platform!r}")
        self._config = config
        self._secret_provider = secret_provider
        self._injected_transport = transport
        self._client: JsonRpcClient | None = None
        self._negotiated_version: str | None = None
        self._authenticated = False

    # ----------------------------------------------------------------- session

    def _resolve_api_key(self) -> str | None:
        """Resolve the API key from its reference at runtime (ADR-010); ``None`` on-box."""
        ref = self._config.api_key_ref
        if ref is None:
            return None  # local-socket root context needs no key (ADD 04)
        if self._secret_provider is None:
            raise AdapterUnavailableError(
                "api_key_ref is set but no secret_provider was supplied to resolve it"
            )
        # Count-only: we never log the reference value or the resolved key (sec-arch §6).
        _log.info("resolving adapter api key", extra={"has_key_ref": True})
        return self._secret_provider(ref)

    def _build_client(self) -> JsonRpcClient:
        if self._injected_transport is not None:
            return JsonRpcClient(self._injected_transport, on_reconnect=self._reauthenticate)
        api_key = self._resolve_api_key()
        transport = build_websocket_transport(
            self._config.endpoint,
            verify_ssl=self._config.verify_ssl,
            api_key=api_key,
        )
        return JsonRpcClient(transport, on_reconnect=self._reauthenticate)

    async def _reauthenticate(self) -> None:
        """Re-run the api-key login after the persistent session dropped and reconnected.

        A long idle scan lets the middleware close the session and expire its auth; the transport
        reconnect alone leaves the new socket unauthenticated, so the resync/topology call would
        fail ENOTAUTHENTICATED and the full-bit guard would (wrongly) fail closed. Re-logging-in on
        reconnect keeps the infrequent control-plane reads working across a long walk.
        """
        if self._client is not None:
            await self._authenticate(self._client)

    async def _session(self) -> JsonRpcClient:
        """Return the live persistent session, opening + authenticating it once."""
        if self._client is None:
            self._client = self._build_client()
        await self._client.connect()
        if not self._authenticated:
            await self._authenticate(self._client)
            self._authenticated = True
        return self._client

    async def _authenticate(self, client: JsonRpcClient) -> None:
        """Authenticate the session: api-key login for remote ``wss``, no-op for on-box socket.

        On-box over the local ``unix`` socket the middleware uses the root context and needs no
        token (ADD 04); a remote endpoint logs in with the user-linked API key. An auth failure
        raises :class:`~fathom.adapters.base.AdapterAuthError` from the client and is **not**
        retried (fail-closed, STRIDE I-2).
        """
        scheme = urlparse(self._config.endpoint).scheme
        if scheme == "unix" and self._config.api_key_ref is None:
            return  # local root context — no login
        api_key = self._resolve_api_key()
        if api_key is None:
            return
        # TODO(truenas-live-verify): confirm the api-key login method name against the live box.
        await client.call("auth.login_with_api_key", [api_key])

    async def probe(self) -> CapabilityManifest:
        """Open the session, negotiate the API version, and report the capability manifest."""
        try:
            client = await self._session()
            self._negotiated_version = await self._negotiate_version(client)
        except AdapterUnavailableError:
            # An unreachable/unauthenticated box yields an api-unavailable manifest rather than
            # crashing; the registry can then fall back to the generic adapter (ADD 04).
            _log.warning("truenas probe failed; reporting api_available=False")
            return CapabilityManifest(
                platform=PlatformClass.TRUENAS.value,
                api_available=False,
                provides=frozenset(),
                api_version=None,
            )
        return CapabilityManifest(
            platform=PlatformClass.TRUENAS.value,
            api_available=True,
            provides=_TRUENAS_PROVIDES,
            api_version=self._negotiated_version,
        )

    async def _negotiate_version(self, client: JsonRpcClient) -> str:
        """Negotiate + record the middleware API version, falling back to the pinned value.

        Pins the configured version (``v25.10``) and records what the middleware actually
        answered so drift is observable in the manifest (ADD 04). A box that does not expose
        the version call still yields the pinned version rather than failing the probe.
        """
        pinned = self._config.api_version
        try:
            # TODO(truenas-live-verify): confirm the version/identity method name on the live box.
            raw = await client.call("core.get_jsonrpc_version")
        except AdapterUnavailableError:
            return pinned
        if isinstance(raw, str) and raw:
            if raw != pinned:
                _log.warning(
                    "truenas api version differs from pin",
                    extra={"negotiated": raw, "pinned": pinned},
                )
            return raw
        return pinned

    # ----------------------------------------------------------------- reads

    async def list_pools(self) -> list[PoolInfo]:
        """Map ``pool.query`` + ``pool.status`` to :class:`PoolInfo` frames (read-only)."""
        client = await self._session()
        rows = await client.call("pool.query")
        pools: list[PoolInfo] = []
        for row in rows if isinstance(rows, list) else []:
            pools.append(self._map_pool(row))
        return pools

    def _map_pool(self, row: dict[str, Any]) -> PoolInfo:
        topology = row.get("topology") or {}
        members = self._pool_members(topology)
        raid_level = self._pool_raid_level(topology)
        usage = row.get("usage") or {}
        return PoolInfo(
            name=str(row.get("name", "")),
            raid_level=raid_level,
            members=members,
            resyncing=self._pool_resyncing(row),
            total=int(usage.get("total", row.get("size", 0)) or 0),
            used=int(usage.get("used", row.get("allocated", 0)) or 0),
            free=int(usage.get("free", row.get("free", 0)) or 0),
        )

    @staticmethod
    def _pool_members(topology: dict[str, Any]) -> list[str]:
        members: list[str] = []
        for vdev in topology.get("data", []) or []:
            for child in vdev.get("children", []) or []:
                name = child.get("disk") or child.get("name")
                if isinstance(name, str):
                    members.append(name)
        return members

    @staticmethod
    def _pool_raid_level(topology: dict[str, Any]) -> str | None:
        data_vdevs = topology.get("data", []) or []
        if not data_vdevs:
            return None
        raw = data_vdevs[0].get("type")
        return str(raw).lower() if isinstance(raw, str) else None

    @staticmethod
    def _pool_resyncing(row: dict[str, Any]) -> bool:
        """True only when an active resilver is in flight (not merely DEGRADED, AR-0002 §5)."""
        scan = row.get("scan") or {}
        scan_state = str(scan.get("function", "")).upper()
        if "RESILVER" in scan_state and str(scan.get("state", "")).upper() in {
            "SCANNING",
            "ACTIVE",
        }:
            return True
        state = str(row.get("status") or row.get("state") or "").upper()
        return state in _RESILVER_STATES

    async def list_disks(self) -> list[DiskInfo]:
        """Map ``disk.query`` to :class:`DiskInfo` frames (transport + SMART, read-only)."""
        client = await self._session()
        rows = await client.call("disk.query")
        disks: list[DiskInfo] = []
        for row in rows if isinstance(rows, list) else []:
            disks.append(self._map_disk(row))
        return disks

    @staticmethod
    def _map_disk(row: dict[str, Any]) -> DiskInfo:
        return DiskInfo(
            name=str(row.get("name", row.get("devname", ""))),
            transport=_coerce_transport(row.get("transfermode") or row.get("bus")),
            size=int(row.get("size", 0) or 0),
            rotational=bool(row.get("rotationrate")) and row.get("type") == "HDD",
            smart_status=(
                str(row["smart_status"]) if row.get("smart_status") is not None else None
            ),
            pool_or_array=row.get("pool") if isinstance(row.get("pool"), str) else None,
        )

    async def volume_usage(self, mountpoint: str) -> tuple[int, int, int]:
        """Return ``(total, used, free)`` for the dataset at ``mountpoint`` via ``pool.dataset``."""
        client = await self._session()
        rows = await client.call("pool.dataset.query", [[["mountpoint", "=", mountpoint]]])
        for row in rows if isinstance(rows, list) else []:
            used = int(self._prop(row, "used"))
            avail = int(self._prop(row, "available"))
            return used + avail, used, avail
        raise AdapterUnavailableError(f"no dataset reported for mountpoint {mountpoint!r}")

    @staticmethod
    def _prop(row: dict[str, Any], key: str) -> int:
        """Read a ZFS dataset property's parsed integer value (TrueNAS nests as {parsed: N})."""
        node = row.get(key)
        if isinstance(node, dict):
            parsed = node.get("parsed", node.get("rawvalue", 0))
            return int(parsed or 0)
        return int(node or 0)

    async def is_array_healthy(self, pool: str) -> bool:
        """Return ``False`` while ``pool`` is resilvering — gates full-bit scans (ADD 02, 16)."""
        for info in await self.list_pools():
            if info.name == pool:
                return not info.resyncing
        # Unknown pool: fail-closed for the safety gate — treat as not-healthy so a full-bit
        # scan does not proceed against a pool we cannot read (ADD 16 hard rule).
        _log.warning("is_array_healthy: pool not found, failing closed", extra={"pool": pool})
        return False

    async def close(self) -> None:
        """Close the persistent session (idempotent)."""
        if self._client is not None:
            await self._client.close()
            self._client = None
            self._authenticated = False
