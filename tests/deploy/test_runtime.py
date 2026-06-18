"""Gating tests for build_deploy_runtime + get_deploy_runtime (default-OFF, fail-loud)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from fathom.api.deploy_runtime import (
    DeploymentProvisioningError,
    build_deploy_runtime,
    get_deploy_runtime,
)
from fathom.core.settings import Settings
from tests.deploy.fakes import FakeSshConnector, make_test_ca

_DB = "sqlite+aiosqlite:///:memory:"


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {"database_url": _DB}
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def _armed_runtime() -> object:
    cert_pem, key_pem = make_test_ca()
    return build_deploy_runtime(
        _settings(
            agent_deployment_enabled=True,
            agent_deployment_ca_cert_ref="CA_CERT",
            agent_deployment_ca_key_ref="CA_KEY",
        ),
        secret_provider=lambda ref: {"CA_CERT": cert_pem, "CA_KEY": key_pem}[ref],
        connector=FakeSshConnector(),
    )


async def test_drain_cancels_inflight_deploy_tasks() -> None:
    # At shutdown, drain() must cancel a still-running deploy task (round-5 F2) so it can't outlive
    # the engine dispose. A long sleep stands in for an in-flight SSH deploy.
    runtime = _armed_runtime()
    assert runtime is not None
    started = asyncio.Event()
    finished = {"v": False}

    async def _slow() -> None:
        started.set()
        await asyncio.sleep(3600)
        finished["v"] = True

    runtime.schedule(_slow())
    await started.wait()
    await runtime.drain(timeout_s=0.05)
    await asyncio.sleep(0.01)  # let the cancellation propagate
    assert finished["v"] is False  # the task was cancelled, not allowed to finish


async def test_drain_noop_without_tasks() -> None:
    runtime = _armed_runtime()
    assert runtime is not None
    await runtime.drain(timeout_s=0.01)  # no tasks → returns immediately


def test_disabled_returns_none() -> None:
    assert build_deploy_runtime(_settings(agent_deployment_enabled=False)) is None


def test_enabled_without_ca_refs_returns_none() -> None:
    assert build_deploy_runtime(_settings(agent_deployment_enabled=True)) is None


def test_enabled_with_ca_builds_runtime() -> None:
    cert_pem, key_pem = make_test_ca()
    runtime = build_deploy_runtime(
        _settings(
            agent_deployment_enabled=True,
            agent_deployment_ca_cert_ref="CA_CERT",
            agent_deployment_ca_key_ref="CA_KEY",
        ),
        secret_provider=lambda ref: {"CA_CERT": cert_pem, "CA_KEY": key_pem}[ref],
        connector=FakeSshConnector(),
    )
    assert runtime is not None
    assert runtime.engine is not None
    assert runtime.enrollment.pending_count() == 0


def test_invalid_ca_material_fails_loud() -> None:
    with pytest.raises(DeploymentProvisioningError):
        build_deploy_runtime(
            _settings(
                agent_deployment_enabled=True,
                agent_deployment_ca_cert_ref="CA_CERT",
                agent_deployment_ca_key_ref="CA_KEY",
            ),
            secret_provider=lambda ref: "garbage",
        )


def test_get_runtime_503_when_unprovisioned() -> None:
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    with pytest.raises(HTTPException) as exc:
        get_deploy_runtime(request)  # type: ignore[arg-type]
    assert exc.value.status_code == 503
