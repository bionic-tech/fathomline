"""STRIDE T-6 — the preview sandbox has no egress (ADR-014; ADD 06 §4 'preview worker no egress').

Named regression gate (STRIDE T-6/E-7): the renderer that decodes untrusted content runs in an
egress-less sandbox. The driver spawns the container with ``--network=none`` (no network
namespace at all), so a decoder-CVE-triggered exfil/callback attempt has no reachable network.
"""

from __future__ import annotations

from fathom.preview.sandbox import RunscSandboxDriver
from fathom.preview.types import ResourceCaps, SupportedType

_CAPS = ResourceCaps(
    cpu=1.0,
    mem_bytes=512 * 1024 * 1024,
    time_s=10.0,
    max_pages=50,
    max_decompressed_bytes=100 * 1024 * 1024,
)


def test_sandbox_has_no_network() -> None:
    """The render container is spawned with no network namespace (no egress; T-6)."""
    driver = RunscSandboxDriver(image="fathom-preview:local")
    argv = driver._argv(caps=_CAPS, job_id="job-1", detected=SupportedType.PDF)
    assert "--network=none" in argv
    # And there is no `--network=<bridge/host>` that would grant egress.
    assert not any(a.startswith("--network=") and a != "--network=none" for a in argv)
    # No published ports either — the worker never listens (no inbound surface).
    assert not any(a in ("-p", "--publish") for a in argv)
