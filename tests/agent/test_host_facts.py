"""Agent host-facts probe tests (ADR-037) — fail-soft detection + GPU parsing.

The probe must never raise (a facts failure must not break a scan) and must return the
``HostFactsFrame`` shape. The NVIDIA path is exercised by stubbing ``shutil.which`` +
``subprocess.run`` so the test needs no GPU.
"""

from __future__ import annotations

import subprocess
from typing import Any

from fathom.agent import host_facts


def test_collect_returns_expected_shape_and_never_raises() -> None:
    facts = host_facts.collect()
    assert set(facts) == {
        "cpu_cores",
        "cpu_model",
        "ram_bytes",
        "gpu_name",
        "gpu_vram_bytes",
        "arch",
    }
    # On the CI/dev host cpu_cores + arch are essentially always knowable.
    assert facts["cpu_cores"] is None or facts["cpu_cores"] >= 1


def test_gpu_parsed_from_nvidia_smi(monkeypatch: Any) -> None:
    monkeypatch.setattr(host_facts.shutil, "which", lambda _name: "/usr/bin/nvidia-smi")

    def fake_run(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout="NVIDIA GeForce RTX 4060, 8192\n", stderr=""
        )

    monkeypatch.setattr(host_facts.subprocess, "run", fake_run)
    name, vram = host_facts._gpu()
    assert name == "NVIDIA GeForce RTX 4060"
    assert vram == 8192 * 1024 * 1024


def test_gpu_absent_is_none(monkeypatch: Any) -> None:
    monkeypatch.setattr(host_facts.shutil, "which", lambda _name: None)
    assert host_facts._gpu() == (None, None)


def test_gpu_smi_failure_is_none(monkeypatch: Any) -> None:
    monkeypatch.setattr(host_facts.shutil, "which", lambda _name: "/usr/bin/nvidia-smi")

    def boom(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("nvidia-smi exploded")

    monkeypatch.setattr(host_facts.subprocess, "run", boom)
    assert host_facts._gpu() == (None, None)
