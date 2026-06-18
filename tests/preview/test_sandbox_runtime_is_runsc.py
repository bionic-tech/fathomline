"""Sandbox driver guards (ADR-014; STRIDE E-7; AR-0002 residual-label foot-gun).

The driver MUST refuse to run if the configured runtime is not ``runsc`` (a silent fall back to
``runc`` would void the gVisor isolation argument — E-7). It must also build a hardened argv:
gVisor runtime, no egress, non-root, read-only, capped, ephemeral.
"""

from __future__ import annotations

import pytest

from fathom.preview.sandbox import RUNSC_RUNTIME, RunscSandboxDriver
from fathom.preview.types import PreviewError, ResourceCaps, SupportedType

_CAPS = ResourceCaps(
    cpu=1.0,
    mem_bytes=512 * 1024 * 1024,
    time_s=10.0,
    max_pages=50,
    max_decompressed_bytes=100 * 1024 * 1024,
)


def test_non_runsc_runtime_refused() -> None:
    """A driver configured with plain runc (or any non-runsc) runtime is refused (E-7)."""
    with pytest.raises(PreviewError):
        RunscSandboxDriver(image="fathom-preview:local", runtime="runc")


def test_runsc_runtime_accepted() -> None:
    driver = RunscSandboxDriver(image="fathom-preview:local", runtime=RUNSC_RUNTIME)
    assert driver is not None


def test_argv_is_hardened() -> None:
    """The spawned argv pins gVisor, no egress, non-root, read-only, capped, ephemeral."""
    driver = RunscSandboxDriver(image="fathom-preview:local")
    argv = driver._argv(caps=_CAPS, job_id="job-1", detected=SupportedType.IMAGE)
    joined = " ".join(argv)
    assert "--runtime=runsc" in argv  # gVisor mandatory (E-7)
    assert "--network=none" in argv  # no egress (T-6/E-7)
    assert "--read-only" in argv
    assert "--user=10001:10001" in argv  # non-root
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert "--rm" in argv  # ephemeral: destroyed after the render
    assert f"--cpus={_CAPS.cpu}" in argv
    assert f"--memory={_CAPS.mem_bytes}" in argv
    assert "--pids-limit=128" in argv
    # The sandbox image (its ENTRYPOINT is `python -m fathom.preview.sandbox_entry`) is the last
    # positional; we append ONLY the per-render arg flags after it (NOT the module — that would
    # double the entrypoint and argparse would reject it). Defence-in-depth caps are passed through.
    assert "fathom-preview:local" in argv
    assert "python -m fathom.preview.sandbox_entry" not in joined  # the image entrypoint owns that
    assert "--type" in argv
    assert "--max-pages" in argv
    assert str(_CAPS.max_pages) in argv
    assert str(_CAPS.max_decompressed_bytes) in argv
