"""TrueNAS adapter behaviour: persistent session, version negotiation, resync guard, fail-closed.

Drives :class:`~fathom.adapters.truenas.TrueNASAdapter` through the fake JSON-RPC transport so
the load-bearing behaviours (ADD 04, ADD 16) are pinned without a live box: one persistent
session that survives a reconnect, pinned-version negotiation, the resync state gating
``LoadSupervisor`` full-bit blocking, and fail-closed handling of revoked keys / unreachable
endpoints / insecure transport.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from fathom.adapters.base import AdapterAuthError, AdapterUnavailableError
from fathom.adapters.config import AdapterConfig
from fathom.adapters.resync import adapter_resync_provider
from fathom.adapters.truenas import TrueNASAdapter
from fathom.agent.config import ThrottleProfile
from fathom.agent.reader.supervisor import LoadSupervisor
from tests.adapters.conftest import (
    DEGRADED_NOT_RESILVERING_POOL,
    HEALTHY_POOL,
    RESILVERING_POOL,
    FakeJsonRpcTransport,
    _default_responder,
)

_KEY_REF = "FATHOM_TRUENAS_KEY"


def _config(**overrides: Any) -> AdapterConfig:
    base: dict[str, Any] = {
        "platform": "truenas",
        "endpoint": "wss://nas.example.test/api/current",
        "api_key_ref": _KEY_REF,
        "endpoint_allowlist": ["nas.example.test"],
    }
    base.update(overrides)
    return AdapterConfig.model_validate(base)


def _adapter(transport: FakeJsonRpcTransport, **cfg: Any) -> TrueNASAdapter:
    return TrueNASAdapter(
        _config(**cfg), secret_provider=lambda _ref: "live-secret", transport=transport
    )


def _throttle() -> ThrottleProfile:
    return ThrottleProfile.model_validate(
        {
            "pause_when": {"load1_above": 100.0, "iowait_above_percent": 100},
            "resume_when": {"load1_below": 1.0},
        }
    )


async def test_probe_reports_negotiated_version() -> None:
    adapter = _adapter(FakeJsonRpcTransport())
    manifest = await adapter.probe()
    assert manifest.api_available is True
    assert manifest.api_version == "v25.10"
    assert "topology" in manifest.provides


async def test_version_mismatch_is_recorded_not_fatal() -> None:
    def responder(method: str, params: Any) -> Any:
        if method == "core.get_jsonrpc_version":
            return "v26.04"  # newer than the pin
        return _default_responder(method, params)

    adapter = _adapter(FakeJsonRpcTransport(responder))
    manifest = await adapter.probe()
    assert manifest.api_available is True
    assert manifest.api_version == "v26.04"  # recorded, not rejected


async def test_persistent_session_survives_reconnect() -> None:
    # Drop the session once mid-stream; the client must reconnect on the SAME transport object
    # (one persistent session, no per-call re-spawn) and the call must still succeed.
    transport = FakeJsonRpcTransport()
    drop = {"armed": True}
    original_recv = transport.recv

    async def flaky_recv() -> str:
        if drop["armed"]:
            drop["armed"] = False
            raise OSError("simulated mid-session drop")
        return await original_recv()

    transport.recv = flaky_recv  # type: ignore[method-assign]
    adapter = _adapter(transport)
    await adapter.probe()  # establishes + authenticates the session
    pools = await adapter.list_pools()  # first recv drops, reconnect, retry succeeds
    assert [p.name for p in pools] == [
        HEALTHY_POOL["name"],
        RESILVERING_POOL["name"],
        DEGRADED_NOT_RESILVERING_POOL["name"],
    ]
    assert transport.connects >= 2  # reconnected, not a fresh adapter/transport


async def test_reconnect_reauthenticates_session() -> None:
    # A long idle scan drops the session AND expires its auth; the transport reconnect must
    # re-run the api-key login, else the retried call fails ENOTAUTHENTICATED and the full-bit
    # resync guard wrongly fails closed (the live TrueNAS symptom). Assert login runs AGAIN.
    logins = {"count": 0}

    def responder(method: str, params: Any) -> Any:
        if method == "auth.login_with_api_key":
            logins["count"] += 1
            return True
        return _default_responder(method, params)

    transport = FakeJsonRpcTransport(responder)
    drop = {"armed": False}
    original_recv = transport.recv

    async def flaky_recv() -> str:
        if drop["armed"]:
            drop["armed"] = False
            raise OSError("simulated idle-session drop")
        return await original_recv()

    transport.recv = flaky_recv  # type: ignore[method-assign]
    adapter = _adapter(transport)
    await adapter.is_array_healthy("tank")  # opens + authenticates (login #1)
    assert logins["count"] == 1
    drop["armed"] = True  # the next call's session has gone idle-dead
    healthy = await adapter.is_array_healthy("tank")  # drop → reconnect → re-login → ok
    assert healthy is True
    assert logins["count"] == 2  # re-authenticated on reconnect


async def test_resilvering_pool_is_unhealthy() -> None:
    adapter = _adapter(FakeJsonRpcTransport())
    assert await adapter.is_array_healthy("raid_set_1") is False  # resilvering
    assert await adapter.is_array_healthy("tank") is True  # healthy


async def test_degraded_but_not_resilvering_is_not_resyncing() -> None:
    # The node-0 nextcloud case: DEGRADED yet NOT resilvering must NOT block full-bit (AR-0002 §5).
    adapter = _adapter(FakeJsonRpcTransport())
    pools = {p.name: p for p in await adapter.list_pools()}
    assert pools["nextcloud"].resyncing is False
    assert await adapter.is_array_healthy("nextcloud") is True


async def test_resync_provider_gates_fullbit_via_supervisor() -> None:
    adapter = _adapter(FakeJsonRpcTransport())
    blocked = LoadSupervisor(
        _throttle(), resync_provider=adapter_resync_provider(adapter, "raid_set_1")
    )
    allowed = LoadSupervisor(_throttle(), resync_provider=adapter_resync_provider(adapter, "tank"))
    assert await blocked.should_block_fullbit_async() is True
    assert await allowed.should_block_fullbit_async() is False


async def test_unknown_pool_fails_closed() -> None:
    adapter = _adapter(FakeJsonRpcTransport())
    # A pool we cannot see must be treated as not-healthy (guard fires) — never silently True.
    assert await adapter.is_array_healthy("ghost-pool") is False


async def test_revoked_key_fails_closed_without_insecure_retry() -> None:
    def responder(method: str, params: Any) -> Any:
        if method == "auth.login_with_api_key":
            return {"__error__": {"code": 401, "message": "token revoked"}}
        return _default_responder(method, params)

    adapter = _adapter(FakeJsonRpcTransport(responder))
    with pytest.raises(AdapterAuthError):
        await adapter.list_pools()


async def test_unreachable_endpoint_raises_unavailable_not_crash() -> None:
    adapter = _adapter(FakeJsonRpcTransport(fail_connect=True))
    # probe() degrades to api_available=False (clean fallback), never raising.
    manifest = await adapter.probe()
    assert manifest.api_available is False
    # A direct read still surfaces the typed unavailable error for the caller to fall back on.
    with pytest.raises(AdapterUnavailableError):
        await adapter.list_pools()


def test_verify_ssl_default_true_and_insecure_refused_outside_lab() -> None:
    cfg = _config()
    assert cfg.verify_ssl is True
    assert cfg.lab_insecure is False
    with pytest.raises(ValueError, match="lab_insecure"):
        _config(verify_ssl=False)
    # A plaintext ws:// endpoint is likewise refused unless the lab profile is set.
    with pytest.raises(ValueError, match="lab_insecure"):
        AdapterConfig.model_validate(
            {
                "platform": "truenas",
                "endpoint": "ws://nas.example.test/api/current",
                "endpoint_allowlist": ["nas.example.test"],
            }
        )


def test_lab_insecure_allows_unverified_transport_loudly() -> None:
    cfg = AdapterConfig.model_validate(
        {
            "platform": "truenas",
            "endpoint": "ws://nas.example.test/api/current",
            "verify_ssl": False,
            "lab_insecure": True,
            "endpoint_allowlist": ["nas.example.test"],
        }
    )
    assert cfg.lab_insecure is True


async def test_no_api_key_material_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    adapter = _adapter(FakeJsonRpcTransport())
    with caplog.at_level(logging.DEBUG, logger="fathom.adapters"):
        await adapter.probe()
        await adapter.list_pools()
    blob = "\n".join(r.getMessage() + str(getattr(r, "__dict__", {})) for r in caplog.records)
    assert "live-secret" not in blob
    assert _KEY_REF not in blob  # the reference name is not leaked either (count-only)


async def test_close_releases_session() -> None:
    transport = FakeJsonRpcTransport()
    adapter = _adapter(transport)
    await adapter.probe()
    await adapter.close()
    assert transport.closed is True
