"""Tests for the fail-fast agent configuration (ADD 02)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fathom.agent.config import AgentConfig, RemoteBackendConfig, ThrottleProfile


def _throttle() -> dict:
    return {
        "pause_when": {"load1_above": 6.0, "iowait_above_percent": 25},
        "resume_when": {"load1_below": 3.0},
    }


def _config(**overrides) -> dict:
    base = {
        "host_id": "nas-1",
        "ingest_url": "https://core.example:8443/api/v1/agents/ingest",
        "client_cert_path": "/etc/fathom/agent.crt",
        "client_key_path": "/etc/fathom/agent.key",
        "server_ca_path": "/etc/fathom/ca.crt",
        "scan_scope": ["/mnt/pool/media"],
        "throttle": _throttle(),
    }
    base.update(overrides)
    return base


def test_valid_config() -> None:
    cfg = AgentConfig.model_validate(_config())
    assert cfg.write_enabled is False  # remediation off by default
    assert cfg.throttle.io_class == "idle"
    assert cfg.scan_scope == ["/mnt/pool/media"]


def test_ingest_url_must_be_https() -> None:
    with pytest.raises(ValidationError, match="https"):
        AgentConfig.model_validate(_config(ingest_url="http://core.example/ingest"))


def test_scan_scope_required_nonempty() -> None:
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_config(scan_scope=[]))


def test_scan_scope_must_be_absolute() -> None:
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_config(scan_scope=["relative/path"]))


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_config(surprise=True))


def test_adapter_config_parsed_with_pool() -> None:
    # On-box TrueNAS adapter over the middleware unix socket (no TLS, api key by-reference) +
    # the pool whose resilver state gates full-bit (ADR-025 scan-fix / AR-0002 §5).
    cfg = AgentConfig.model_validate(
        _config(
            adapter={
                "platform": "truenas",
                "endpoint": "unix:///run/middleware/middlewared.sock",
                "api_key_ref": "fathom_truenas_apikey",
            },
            adapter_pool="tank",
        )
    )
    assert cfg.adapter is not None
    assert cfg.adapter.endpoint == "unix:///run/middleware/middlewared.sock"
    assert cfg.adapter_pool == "tank"


def test_adapter_requires_pool() -> None:
    with pytest.raises(ValidationError, match="adapter_pool"):
        AgentConfig.model_validate(
            _config(
                adapter={
                    "platform": "truenas",
                    "endpoint": "unix:///run/middleware/middlewared.sock",
                    "api_key_ref": "r",
                }
            )
        )


def test_build_adapter_truenas_and_none() -> None:
    from fathom.adapters.truenas import TrueNASAdapter
    from fathom.agent.__main__ import _build_adapter

    assert _build_adapter(AgentConfig.model_validate(_config())) is None
    cfg = AgentConfig.model_validate(
        _config(
            adapter={
                "platform": "truenas",
                "endpoint": "unix:///run/middleware/middlewared.sock",
                "api_key_ref": "r",
            },
            adapter_pool="tank",
        )
    )
    assert isinstance(_build_adapter(cfg), TrueNASAdapter)


def test_resume_must_be_below_pause() -> None:
    bad = _throttle()
    bad["resume_when"]["load1_below"] = 9.0  # >= pause ceiling
    with pytest.raises(ValidationError, match="hysteresis"):
        ThrottleProfile.model_validate(bad)


def test_in_scope() -> None:
    cfg = AgentConfig.model_validate(_config(scan_scope=["/mnt/pool/media", "/srv/data"]))
    assert cfg.in_scope("/mnt/pool/media/movies") is True
    assert cfg.in_scope("/mnt/pool/media") is True
    assert cfg.in_scope("/etc/passwd") is False
    assert cfg.in_scope("/mnt/pool/other") is False
    assert cfg.in_scope("relative") is False


def test_fullbit_scope_defaults_empty() -> None:
    cfg = AgentConfig.model_validate(_config())
    assert cfg.fullbit_scope == []
    # Empty allow-list → full-bit is opt-in, never implicit.
    assert cfg.in_fullbit_scope("/mnt/pool/media/movies") is False


def test_fullbit_scope_subset_allowed() -> None:
    cfg = AgentConfig.model_validate(
        _config(scan_scope=["/mnt/pool/media"], fullbit_scope=["/mnt/pool/media/movies"])
    )
    assert cfg.in_fullbit_scope("/mnt/pool/media/movies/a.mkv") is True
    assert cfg.in_fullbit_scope("/mnt/pool/media/photos") is False


def test_fullbit_scope_must_be_within_scan_scope() -> None:
    with pytest.raises(ValidationError, match="not within scan_scope"):
        AgentConfig.model_validate(
            _config(scan_scope=["/mnt/pool/media"], fullbit_scope=["/srv/other"])
        )


# --------------------------------------------------------------------- RemoteBackendConfig (010)


def test_remote_backend_config_smb_valid() -> None:
    rc = RemoteBackendConfig(protocol="smb", host="nas.example", share="media", remote_path="/m")
    assert rc.mount_key == "smb://nas.example/media/m"
    # Credentials are references only — there is no field that can carry key material.
    assert rc.password_ref is None


def test_remote_backend_config_sftp_mount_key() -> None:
    rc = RemoteBackendConfig(protocol="sftp", host="nas.example", remote_path="/home/u")
    assert rc.mount_key == "sftp://nas.example/home/u"


def test_remote_backend_config_smb_requires_share() -> None:
    with pytest.raises(ValidationError, match="share"):
        RemoteBackendConfig(protocol="smb", host="nas.example", remote_path="/m")


def test_remote_backend_config_host_rejects_scheme_or_path() -> None:
    with pytest.raises(ValidationError):
        RemoteBackendConfig(protocol="sftp", host="sftp://nas.example", remote_path="/m")
    with pytest.raises(ValidationError):
        RemoteBackendConfig(protocol="sftp", host="nas.example/share", remote_path="/m")


def test_remote_backend_config_verify_false_requires_lab_insecure() -> None:
    with pytest.raises(ValidationError, match="lab_insecure"):
        RemoteBackendConfig(protocol="sftp", host="nas.example", remote_path="/m", verify=False)
    # Explicit lab opt-in is allowed (loud, deliberate).
    rc = RemoteBackendConfig(
        protocol="sftp", host="nas.example", remote_path="/m", verify=False, lab_insecure=True
    )
    assert rc.verify is False


def test_remote_backend_config_extra_forbidden() -> None:
    with pytest.raises(ValidationError):
        RemoteBackendConfig(
            protocol="sftp",
            host="nas.example",
            remote_path="/m",
            api_key="oops",  # type: ignore[call-arg]
        )


def test_remote_backend_config_rejects_path_traversal() -> None:
    # ADR-029/AR-0012: a `..` segment would let catalogue_mount normalise out of the synthetic
    # namespace into a real local path (e.g. /sftp/h/../../etc → /etc) and alias another volume.
    with pytest.raises(ValidationError, match="traversal"):
        RemoteBackendConfig(protocol="sftp", host="nas.example", remote_path="/../../etc")
    with pytest.raises(ValidationError, match="traversal"):
        RemoteBackendConfig(
            protocol="smb", host="nas.example", share="../../../mnt/data", remote_path="/m"
        )
    with pytest.raises(ValidationError, match="traversal"):
        RemoteBackendConfig(protocol="rclone", host="gdrive", remote_path="/a/../../mnt")


def test_remote_backend_config_rejects_control_and_backslash() -> None:
    with pytest.raises(ValidationError, match="control"):
        RemoteBackendConfig(protocol="sftp", host="nas.example", remote_path="/a\x7fb")
    with pytest.raises(ValidationError, match="backslash"):
        RemoteBackendConfig(protocol="sftp", host="nas.example", remote_path="/a\\b")


def test_remote_backend_config_catalogue_mount_is_canonical() -> None:
    # ADR-029: catalogue_mount must be POSIX-canonical so the server's mountpoint re-vet (which
    # re-runs normpath) accepts it. A safe but cosmetically non-canonical remote_path/share — a
    # `//` or `/./` segment — must be normalised here, else ingest would 422 every push.
    from fathom.security.paths import validate_config_path

    cases = [
        (dict(protocol="sftp", host="h", remote_path="/data//sub"), "/sftp/h/data/sub"),
        (dict(protocol="sftp", host="h", remote_path="/a/./b"), "/sftp/h/a/b"),
        (dict(protocol="rclone", host="h", remote_path="/a//b"), "/rclone/h/a/b"),
        (dict(protocol="smb", host="h", share="media", remote_path="/x//y"), "/smb/h/media/x/y"),
    ]
    for kwargs, expected in cases:
        rc = RemoteBackendConfig(**kwargs)  # type: ignore[arg-type]
        assert rc.catalogue_mount == expected
        # The point: it equals its own canonical form, so the ingest re-vet passes (no false 422).
        assert str(validate_config_path(rc.catalogue_mount)) == rc.catalogue_mount


def test_agent_config_carries_remote_targets() -> None:
    cfg = AgentConfig.model_validate(
        _config(
            remote_targets=[
                {"protocol": "sftp", "host": "nas.example", "remote_path": "/share"},
            ]
        )
    )
    assert len(cfg.remote_targets) == 1
    assert cfg.remote_targets[0].mount_key == "sftp://nas.example/share"
