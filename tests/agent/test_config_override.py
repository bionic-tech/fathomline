"""AgentConfig.reportable() + with_override() — ADR-033 (#9 report, #10 override, fail-safe)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fathom.agent.config import AgentConfig

_BASE = {
    "host_id": "nas-1",
    "ingest_url": "https://proxy:9443/api/v1/agents/ingest",
    "client_cert_path": "/certs/client.crt",
    "client_key_path": "/certs/client.key",
    "server_ca_path": "/certs/fathom-ca.crt",
    "scan_scope": ["/scan/data", "/scan/media"],
    "fullbit_scope": ["/scan/data"],
    "cross_mounts": False,
    "throttle": {
        "io_max_mbps": 80,
        "pause_when": {"load1_above": 20.0, "iowait_above_percent": 25.0},
        "resume_when": {"load1_below": 10.0},
    },
}


def _cfg(**over: object) -> AgentConfig:
    return AgentConfig.model_validate({**_BASE, **over})


def test_reportable_is_the_observable_config_without_secrets() -> None:
    rep = _cfg().reportable()
    assert rep["scan_scope"] == ["/scan/data", "/scan/media"]
    assert rep["fullbit_scope"] == ["/scan/data"]
    assert rep["exclude_scope"] == []  # ADR-034: present (empty by default), shown in the UI
    assert rep["cross_mounts"] is False
    assert rep["write_enabled"] is False
    assert rep["throttle"]["io_max_mbps"] == 80
    # never leaks cert/secret/identity-transport fields
    for leak in ("client_cert_path", "client_key_path", "server_ca_path", "ingest_url", "host_id"):
        assert leak not in rep


def test_with_override_applies_only_overridable_fields() -> None:
    merged = _cfg().with_override(
        {
            "scan_scope": ["/scan/data"],
            "cross_mounts": True,
            "throttle": {
                "io_max_mbps": 50,
                "pause_when": {"load1_above": 10.0, "iowait_above_percent": 15.0},
                "resume_when": {"load1_below": 5.0},
            },
        }
    )
    assert merged.scan_scope == ["/scan/data"]
    assert merged.cross_mounts is True
    assert merged.throttle.io_max_mbps == 50
    # fullbit unchanged (still a subset of the narrowed scope) + identity preserved
    assert merged.fullbit_scope == ["/scan/data"]
    assert merged.host_id == "nas-1"


def test_with_override_ignores_non_overridable_keys() -> None:
    # Even if a non-overridable key sneaks into the dict, with_override must NOT honour it.
    merged = _cfg().with_override(
        {
            "host_id": "evil",
            "ingest_url": "https://attacker/x",
            "write_enabled": True,
            "client_cert_path": "/tmp/x",
            "scan_scope": ["/scan/data"],
        }
    )
    assert merged.host_id == "nas-1"  # identity untouched
    assert merged.ingest_url == _BASE["ingest_url"]
    assert merged.write_enabled is False  # write path NOT remotely enableable
    assert merged.client_cert_path == "/certs/client.crt"
    assert merged.scan_scope == ["/scan/data"]  # only the safe field applied


def test_with_override_applies_exclude_scope() -> None:
    # ADR-034: exclude_scope is overridable; it is reported, and is_excluded() honours the subtree.
    merged = _cfg().with_override({"exclude_scope": ["/scan/data/cache", "/scan/media/tmp"]})
    assert merged.exclude_scope == ["/scan/data/cache", "/scan/media/tmp"]
    assert merged.reportable()["exclude_scope"] == ["/scan/data/cache", "/scan/media/tmp"]
    assert merged.is_excluded("/scan/data/cache") is True
    assert merged.is_excluded("/scan/data/cache/sub/file") is True  # subtree
    assert merged.is_excluded("/scan/data/cache-other") is False  # sibling, not a subtree
    assert merged.is_excluded("/scan/data/keep") is False


def test_with_override_empty_is_noop() -> None:
    cfg = _cfg()
    assert cfg.with_override({}) is cfg
    assert cfg.with_override({"write_enabled": True}) is cfg  # all-unknown → no-op


def test_with_override_invalid_merge_raises_for_failsafe() -> None:
    # fullbit_scope must be a subset of scan_scope — an override that narrows scan_scope below the
    # fullbit set produces an invalid config; with_override RAISES so the agent keeps local config.
    with pytest.raises(ValidationError):
        _cfg().with_override({"scan_scope": ["/scan/media"]})  # drops /scan/data, still in fullbit
