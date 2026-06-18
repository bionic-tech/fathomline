"""runsc (gVisor) sandbox driver — one ephemeral container per render (ADR-014; STRIDE E-7/T-6).

The :class:`SandboxDriver` protocol takes one untrusted file's raw bytes and returns DERIVED
artifacts. The production :class:`RunscSandboxDriver` enforces the owner ruling exactly:

* **one ephemeral ``runsc`` container per render**, ``--rm`` so it is destroyed after (ADR-014);
* **gVisor mandatory** — ``--runtime=runsc``; the driver refuses to run if the configured runtime
  is not ``runsc`` (the AR-0002 residual-label foot-gun: a silent fall back to ``runc`` voids the
  isolation argument, so we fail-closed rather than render under plain runc — E-7);
* **no egress** — ``--network=none`` (T-6/E-7; ADD 06 §4 "preview worker no egress");
* **non-root**, **read-only rootfs**, **no extra capabilities**, ``no-new-privileges`` (E-7);
* **per-render caps** from :class:`~fathom.preview.types.ResourceCaps` — ``--cpus``, ``--memory``,
  ``--pids-limit``, a tmpfs scratch, and a hard **wall-clock timeout** that kills the container on
  breach (decompression/page bombs killed → STRIDE D-6);
* the single file is streamed in over **stdin** and the derived artifacts come back as JSON on
  **stdout** — no broad mount, no shared filesystem (owner ruling: no broad mount).

The driver does **not** decode anything in-process: the decode happens inside the container via
``python -m fathom.preview.sandbox_entry`` (the renderers run there). This file only spawns,
caps, times-out, and parses the result — so importing it pulls in no decoder library.
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Protocol

from fathom.logging import get_logger
from fathom.preview.types import (
    PreviewArtifact,
    PreviewError,
    ResourceCaps,
    SupportedType,
)

_log = get_logger("fathom.preview.sandbox")

RUNSC_RUNTIME = "runsc"


class SandboxDriver(Protocol):
    """Run one untrusted file through an ephemeral sandbox and return derived artifacts.

    ``job_id`` is the per-render id (audit/log correlation). On any cap breach / failure the
    implementation kills the render and raises
    :class:`~fathom.preview.types.PreviewError` — it never returns raw bytes.
    """

    async def run(
        self,
        raw: bytes,
        *,
        detected: SupportedType,
        caps: ResourceCaps,
        job_id: str,
    ) -> list[PreviewArtifact]: ...


class RunscSandboxDriver:
    """Spawn ``docker run --runtime=runsc`` per render — gVisor, no egress, non-root, capped.

    ``runtime`` is validated against :data:`RUNSC_RUNTIME` at construction so a mis-configured
    deployment (the AR-0002 residual ``runsc`` label that silently falls back to ``runc``) is
    refused up front rather than rendering untrusted content under weak isolation (E-7).
    """

    def __init__(
        self,
        *,
        image: str,
        runtime: str = RUNSC_RUNTIME,
        docker_bin: str = "docker",
    ) -> None:
        if runtime != RUNSC_RUNTIME:
            # Fail-closed: the whole safety argument rests on gVisor. Refuse plain runc (E-7).
            raise PreviewError(
                f"preview sandbox runtime must be {RUNSC_RUNTIME!r}, not {runtime!r}",
                status_code=500,
            )
        self._image = image
        self._runtime = runtime
        self._docker = docker_bin

    def _argv(self, *, caps: ResourceCaps, job_id: str, detected: SupportedType) -> list[str]:
        """Build the hardened ``docker run`` argv (gVisor, no egress, non-root, capped)."""
        return [
            self._docker,
            "run",
            "--rm",  # ephemeral: destroyed after the render (ADR-014)
            f"--runtime={self._runtime}",  # gVisor mandatory (E-7)
            "--network=none",  # no egress (T-6/E-7)
            "--read-only",  # read-only rootfs
            "--user=10001:10001",  # non-root
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--cpus={caps.cpu}",
            f"--memory={caps.mem_bytes}",
            "--memory-swap",
            str(caps.mem_bytes),  # disable swap → memory cap is hard (D-6)
            "--pids-limit=128",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",  # scratch only; noexec
            "-i",  # stream the single file in over stdin
            f"--name=preview-{job_id}",
            self._image,
            # The image ENTRYPOINT is ``python -m fathom.preview.sandbox_entry``
            # (Dockerfile.preview); append ONLY its args here. Repeating the module would pass it
            # as argv to the entrypoint and argparse would reject it ("unrecognized arguments") —
            # every render then fails rc=2.
            "--type",
            detected.value,
            "--max-pages",
            str(caps.max_pages),
            "--max-decompressed-bytes",
            str(caps.max_decompressed_bytes),
        ]

    async def run(
        self,
        raw: bytes,
        *,
        detected: SupportedType,
        caps: ResourceCaps,
        job_id: str,
    ) -> list[PreviewArtifact]:
        argv = self._argv(caps=caps, job_id=job_id, detected=detected)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(
                proc.communicate(input=raw), timeout=caps.time_s
            )
        except TimeoutError as exc:
            # Wall-clock cap breached (bomb / hang) → kill the container, fail gracefully (D-6).
            await self._kill(proc, job_id)
            raise PreviewError("preview render timed out", status_code=504) from exc

        if proc.returncode != 0:
            _log.warning(
                "preview sandbox render failed",
                extra={"job_id": job_id, "rc": proc.returncode, "type": detected.value},
            )
            raise PreviewError("preview render failed")
        return _parse_artifacts(stdout)

    async def _kill(self, proc: asyncio.subprocess.Process, job_id: str) -> None:
        """Kill the timed-out render process and best-effort remove the container (ephemerality)."""
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:  # pragma: no cover — already gone
            pass
        try:
            rm = await asyncio.create_subprocess_exec(
                self._docker,
                "rm",
                "-f",
                f"preview-{job_id}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await rm.wait()
        except OSError:  # pragma: no cover — docker absent; the --rm already covers the happy path
            pass


def _parse_artifacts(stdout: bytes) -> list[PreviewArtifact]:
    """Parse the sandbox entrypoint's JSON stdout into derived artifacts (fail-closed).

    The entrypoint emits ``{"artifacts": [{"kind","media_type","data_b64","meta"}, ...]}``; the
    bytes are base64 so the JSON channel stays text. A malformed payload is a render failure, not
    a 500 with internals.
    """
    try:
        payload = json.loads(stdout)
        raw_artifacts = payload["artifacts"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise PreviewError("preview render produced no valid artifact") from exc
    artifacts: list[PreviewArtifact] = []
    for item in raw_artifacts:
        try:
            artifacts.append(
                PreviewArtifact(
                    kind=item["kind"],
                    media_type=item["media_type"],
                    data=base64.b64decode(item["data_b64"]),
                    meta=item.get("meta", {}),
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise PreviewError("preview render produced a malformed artifact") from exc
    if not artifacts:
        raise PreviewError("preview render produced no artifact")
    return artifacts
