"""Tests for the agent config loader (YAML/JSON → AgentConfig)."""

from __future__ import annotations

from pathlib import Path

import pytest

from fathom.agent.loader import load_agent_config

_VALID_YAML = """
host_id: nas-1
ingest_url: https://proxy:8443/api/v1/agents/ingest
client_cert_path: /certs/client.crt
client_key_path: /certs/client.key
server_ca_path: /certs/fathom-ca.crt
scan_scope:
  - /scan/tank
throttle:
  walk_concurrency: 4
  hash_concurrency: 2
  pause_when:
    load1_above: 20.0
    iowait_above_percent: 25
  resume_when:
    load1_below: 12.0
"""


def test_load_valid_yaml(tmp_path: Path) -> None:
    p = tmp_path / "agent.yaml"
    p.write_text(_VALID_YAML)
    config = load_agent_config(p)
    assert config.host_id == "nas-1"
    assert config.scan_scope == ["/scan/tank"]
    assert config.throttle.walk_concurrency == 4
    assert config.write_enabled is False  # safe default


def test_rejects_non_mapping(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(ValueError, match="must be a mapping"):
        load_agent_config(p)


def test_rejects_http_ingest_url(tmp_path: Path) -> None:
    p = tmp_path / "insecure.yaml"
    p.write_text(_VALID_YAML.replace("https://", "http://"))
    with pytest.raises(ValueError, match="https"):
        load_agent_config(p)
