"""STRIDE D-6 — decompression / huge-page bombs are killed within caps (ADR-014).

Named regression gate (STRIDE D-6): a crafted bomb input must be killed within the per-render
caps and fail gracefully (a sanitised error), never OOM or hang. Two layers are asserted:

1. the renderer-level decompressed-bytes cap refuses an over-cap input *before* decoding
   (defence in depth inside the sandbox);
2. the sandbox driver's wall-clock timeout kills a hung/looping render and raises a graceful
   :class:`PreviewError`, rather than blocking forever.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from fathom.preview.renderers.document import DocumentRenderer
from fathom.preview.renderers.text import TextRenderer
from fathom.preview.sandbox import RunscSandboxDriver
from fathom.preview.types import PreviewError, ResourceCaps, SupportedType

_SMALL_CAPS = ResourceCaps(
    cpu=1.0,
    mem_bytes=64 * 1024 * 1024,
    time_s=0.5,  # tiny wall-clock for the timeout-kill assertion
    max_pages=2,
    max_decompressed_bytes=1024 * 1024,  # 1 MiB decompressed cap
)


def test_renderer_refuses_over_cap_input_gracefully() -> None:
    """An input over the decompressed-bytes cap is refused gracefully, not OOM'd (D-6)."""
    bomb = b"A" * (2 * 1024 * 1024)  # 2 MiB > 1 MiB cap
    with pytest.raises(PreviewError):
        DocumentRenderer().render(bomb, detected=SupportedType.PDF, caps=_SMALL_CAPS)
    with pytest.raises(PreviewError):
        TextRenderer().render(bomb, detected=SupportedType.TEXT, caps=_SMALL_CAPS)


async def test_sandbox_driver_kills_on_timeout(tmp_path: Path) -> None:
    """A render that exceeds the wall-clock cap is killed and fails gracefully, not hung (D-6)."""
    # A fake `docker` that ignores its args and sleeps far past the cap → the driver must time it
    # out and kill it. This proves the wall-clock guard fires without a real runsc container.
    fake_docker = tmp_path / "docker"
    fake_docker.write_text("#!/bin/sh\nsleep 30\n")
    fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    os.environ.setdefault("PATH", "/usr/bin")

    driver = RunscSandboxDriver(image="fathom-preview:local", docker_bin=str(fake_docker))
    with pytest.raises(PreviewError):
        await driver.run(b"hang-me", detected=SupportedType.TEXT, caps=_SMALL_CAPS, job_id="bomb-1")
