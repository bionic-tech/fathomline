"""Preview runtime wiring — the render pipeline + queue the route consumes (ADR-014).

Like the remediation runtime, the preview route needs collaborators it cannot build itself: the
:class:`~fathom.preview.service.PreviewService` (cache + sandbox driver + signed-pull fetcher) and
the bounded :class:`~fathom.workers.preview.PreviewQueue`. These are injected onto
``app.state.preview_runtime`` at enablement so the route handler stays thin and tests can supply a
fake sandbox driver / file fetcher without spawning a real ``runsc`` container.

Default posture (fail-closed): if no runtime is configured (preview not provisioned), :func:`
get_preview_runtime` raises 503 — the preview path is genuinely unavailable until a deliberate
enablement step wires the sandbox driver + signing key + cache. There is no silent default that
could mask a mis-enabled deployment (mirrors remediation_runtime).
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from fathom.preview.service import PreviewService
from fathom.workers.preview import PreviewQueue


@dataclass(frozen=True, slots=True)
class PreviewRuntime:
    """The injectable collaborators for the preview path (service + concurrency queue)."""

    service: PreviewService
    queue: PreviewQueue


def get_preview_runtime(request: Request) -> PreviewRuntime:
    """Return the configured preview runtime, or 503 if it is not provisioned (default)."""
    runtime = getattr(request.app.state, "preview_runtime", None)
    if not isinstance(runtime, PreviewRuntime):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="preview runtime not provisioned (no sandbox driver / cache)",
        )
    return runtime


__all__ = ["PreviewRuntime", "get_preview_runtime"]
