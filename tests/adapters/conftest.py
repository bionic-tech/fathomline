"""Shared adapter-test fixtures: a fake JSON-RPC WebSocket transport + canned NAS payloads.

The fake transport satisfies the :class:`~fathom.adapters.jsonrpc.JsonRpcTransport` Protocol so
the TrueNAS adapter's mappers are exercised against fixtures with no live box (ADD 04 risk
mitigation). Payloads model a realistic estate: a healthy draid1 pool (nas-1 ``tank``),
a resilvering pool, and a DEGRADED-but-not-resilvering pool (the node-0 ``nextcloud`` evidence,
AR-0002 §5) so the resync guard's discrimination is testable.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

# --- canned middleware payloads (shape modelled on the documented JSON-RPC surface) ---------

HEALTHY_POOL: dict[str, Any] = {
    "name": "tank",
    "status": "ONLINE",
    "scan": {"function": "SCRUB", "state": "FINISHED"},
    "topology": {
        "data": [
            {
                "type": "DRAID1",
                "children": [
                    {"disk": "nvme0n1"},
                    {"disk": "nvme1n1"},
                    {"disk": "sda"},
                ],
            }
        ]
    },
    "usage": {"total": 136_000_000_000_000, "used": 40_000_000_000_000, "free": 96_000_000_000_000},
}

RESILVERING_POOL: dict[str, Any] = {
    "name": "raid_set_1",
    "status": "ONLINE",
    "scan": {"function": "RESILVER", "state": "SCANNING"},
    "topology": {
        "data": [
            {
                "type": "RAIDZ1",
                "children": [{"disk": "sdb"}, {"disk": "sdc"}, {"disk": "sdd"}],
            }
        ]
    },
    "usage": {"total": 16_000_000_000_000, "used": 8_000_000_000_000, "free": 8_000_000_000_000},
}

DEGRADED_NOT_RESILVERING_POOL: dict[str, Any] = {
    # node-0 nextcloud: DEGRADED, 40 errors, last resilver long finished — unhealthy but NOT
    # resyncing, so it must not trip the full-bit guard (AR-0002 §5).
    "name": "nextcloud",
    "status": "DEGRADED",
    "scan": {"function": "RESILVER", "state": "FINISHED"},
    "topology": {
        "data": [
            {
                "type": "RAIDZ1",
                "children": [{"disk": "sde"}, {"disk": "sdf"}, {"disk": "sdg"}],
            }
        ]
    },
    "usage": {"total": 15_400_000_000_000, "used": 14_900_000_000_000, "free": 500_000_000_000},
}

DISKS: list[dict[str, Any]] = [
    {
        "name": "nvme0n1",
        "bus": "NVME",
        "size": 2_000_000_000_000,
        "type": "SSD",
        "rotationrate": None,
        "smart_status": "PASS",
        "pool": "tank",
    },
    {
        "name": "sda",
        "bus": "SATA",
        "size": 8_000_000_000_000,
        "type": "HDD",
        "rotationrate": 7200,
        "smart_status": "PASS",
        "pool": "tank",
    },
]

DATASETS: list[dict[str, Any]] = [
    {
        "name": "tank/Docker",
        "mountpoint": "/mnt/tank/Docker",
        "used": {"parsed": 65_000_000_000},
        "available": {"parsed": 96_000_000_000_000},
    }
]


def _default_responder(method: str, params: list[Any] | dict[str, Any]) -> Any:
    """Map a JSON-RPC method to its canned result (the healthy-estate baseline)."""
    if method == "auth.login_with_api_key":
        return True
    if method == "core.get_jsonrpc_version":
        return "v25.10"
    if method == "pool.query":
        return [HEALTHY_POOL, RESILVERING_POOL, DEGRADED_NOT_RESILVERING_POOL]
    if method == "disk.query":
        return DISKS
    if method == "pool.dataset.query":
        return DATASETS
    raise KeyError(f"no canned response for {method!r}")


class FakeJsonRpcTransport:
    """An in-memory :class:`JsonRpcTransport` that answers calls from a responder function.

    ``responder(method, params) -> result`` lets a test override individual methods (e.g. to
    raise an auth error or drop the connection); the default models the healthy estate.
    """

    def __init__(
        self,
        responder: Callable[[str, Any], Any] | None = None,
        *,
        fail_connect: bool = False,
    ) -> None:
        self._responder = responder or _default_responder
        self._fail_connect = fail_connect
        self._outbox: list[str] = []
        self.connects = 0
        self.closed = False

    async def connect(self) -> None:
        self.connects += 1
        if self._fail_connect:
            raise OSError("simulated unreachable endpoint")

    async def send(self, message: str) -> None:
        request = json.loads(message)
        result = self._responder(request["method"], request.get("params"))
        if isinstance(result, dict) and "__error__" in result:
            envelope = {"jsonrpc": "2.0", "id": request["id"], "error": result["__error__"]}
        else:
            envelope = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        self._outbox.append(json.dumps(envelope))

    async def recv(self) -> str:
        if not self._outbox:
            raise OSError("no frame queued")
        return self._outbox.pop(0)

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_transport() -> FakeJsonRpcTransport:
    """A fake transport pre-loaded with the healthy-estate canned payloads."""
    return FakeJsonRpcTransport()
