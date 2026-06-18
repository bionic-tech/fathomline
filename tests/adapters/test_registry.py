"""AdapterRegistry resolution, the SSRF endpoint allowlist, and discovery suggestion (ADD 04).

Covers first-match-by-platform-class resolution, the operator-confirmed-class contract, the
:class:`NoAdapterError` fail-closed path, the SSRF policy (private NAS allowlisted, metadata
hard-blocked), and the non-authoritative :func:`suggest_platform` hint.
"""

from __future__ import annotations

import pytest

from fathom.adapters import (
    AdapterRegistry,
    GenericLinuxAdapter,
    NoAdapterError,
    PlatformClass,
    ProbeSignals,
    suggest_platform,
)
from fathom.adapters.config import AdapterConfig, SsrfError, assert_endpoint_allowed


def test_first_match_resolution_and_priority() -> None:
    registry = AdapterRegistry()
    first = GenericLinuxAdapter()
    second = GenericLinuxAdapter()
    registry.register(PlatformClass.GENERIC_LINUX, first)
    registry.register(PlatformClass.GENERIC_LINUX, second)
    # Registered earlier = higher priority (mirrors BackendRegistry).
    assert registry.resolve(PlatformClass.GENERIC_LINUX) is first


def test_resolves_by_operator_confirmed_class() -> None:
    registry = AdapterRegistry()
    generic = GenericLinuxAdapter()
    registry.register(PlatformClass.GENERIC_LINUX, generic)
    assert registry.resolve(PlatformClass.GENERIC_LINUX) is generic


def test_unregistered_class_raises_no_adapter_error() -> None:
    registry = AdapterRegistry()
    registry.register(PlatformClass.GENERIC_LINUX, GenericLinuxAdapter())
    with pytest.raises(NoAdapterError):
        registry.resolve(PlatformClass.TRUENAS)


def test_register_rejects_non_adapter() -> None:
    registry = AdapterRegistry()
    with pytest.raises(TypeError):
        registry.register(PlatformClass.GENERIC_LINUX, object())  # type: ignore[arg-type]


# --- SSRF policy -----------------------------------------------------------------------------


def test_allowlist_accepts_private_nas_target() -> None:
    # The intended case: a private NAS IP is fine *because* it is on the operator allowlist.
    assert_endpoint_allowed("wss://192.168.1.86/api/current", frozenset({"192.168.1.86"}))


def test_allowlist_rejects_unlisted_host() -> None:
    with pytest.raises(SsrfError):
        assert_endpoint_allowed("wss://10.0.0.5/api/current", frozenset({"192.168.1.86"}))


def test_metadata_ip_hard_blocked_even_if_allowlisted() -> None:
    # 169.254.169.254 must NEVER be reachable, allowlist or not (owner ruling).
    with pytest.raises(SsrfError, match="metadata"):
        assert_endpoint_allowed("wss://169.254.169.254/api/current", frozenset({"169.254.169.254"}))


def test_local_socket_needs_no_allowlist() -> None:
    # The on-box unix socket has no network host to forge — always permitted.
    assert_endpoint_allowed("unix:///var/run/middlewared.sock", frozenset())


def test_config_enforces_allowlist_at_validation() -> None:
    with pytest.raises(ValueError, match="allowlist"):
        AdapterConfig.model_validate(
            {
                "platform": "truenas",
                "endpoint": "wss://nas.example.test/api/current",
                "endpoint_allowlist": [],  # host not listed → rejected fail-closed
            }
        )


# --- discovery suggestion (non-authoritative) ------------------------------------------------


def test_suggest_truenas_from_banner() -> None:
    signals = ProbeSignals(version_banner="TrueNAS-SCALE-25.10.1")
    assert suggest_platform(signals) is PlatformClass.TRUENAS


def test_suggest_falls_back_to_os_family() -> None:
    assert suggest_platform(ProbeSignals(os_family="linux")) is PlatformClass.GENERIC_LINUX
    assert suggest_platform(ProbeSignals(os_family="windows")) is PlatformClass.GENERIC_WINDOWS


def test_suggest_returns_none_when_unsure() -> None:
    # No distinctive signal → None, so the operator is prompted rather than misclassified.
    assert suggest_platform(ProbeSignals()) is None
