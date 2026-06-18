"""Preview render WORKER route (ADR-014) — the gVisor side of the distributed render split.

Active ONLY on the preview-worker instance (``preview_worker_enabled``). The core POSTs the
already-fetched file's raw bytes here; the worker runs ONE ephemeral ``runsc`` sandbox per render
and returns DERIVED ARTIFACTS ONLY. The core itself cannot run ``runsc`` (TrueNAS, AR-0002), which
is the entire reason this hop exists.

Authenticated by the shared ``X-Fathom-Proxy-Secret`` (the same secret the mTLS proxy stamps, which
the core and worker both hold) — a request without it is refused. On the core (worker disabled) the
route 503s, so it is inert there. This route carries untrusted file bytes, but never decodes them:
the decode happens only inside the gVisor sandbox (``RunscSandboxDriver`` → ``sandbox_entry``).
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request, status

from fathom.api.deps import SettingsDep
from fathom.logging import get_logger
from fathom.preview.remote_driver import RenderRequest, RenderResponse, render_request
from fathom.preview.sandbox import RunscSandboxDriver
from fathom.preview.types import PreviewError

_log = get_logger("fathom.api.routers.worker_render")

router = APIRouter(prefix="/api/v1/preview", tags=["preview-worker"])

_SECRET_HEADER = "X-Fathom-Proxy-Secret"  # noqa: S105 - an HTTP header name, not a secret value


@router.post("/render", response_model=RenderResponse)
async def render(
    payload: RenderRequest,
    settings: SettingsDep,
    request: Request,
) -> RenderResponse:
    """Render one file's bytes in an ephemeral gVisor sandbox and return derived artifacts."""
    if not settings.preview_worker_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="this instance is not a preview render worker",
        )
    expected = settings.ingest_proxy_secret
    presented = request.headers.get(_SECRET_HEADER, "")
    if not expected or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing worker secret"
        )
    try:
        # Construct per-request: the E-7 runtime check (must be 'runsc') fails closed here, so a
        # mis-configured worker refuses to render rather than silently falling back to runc.
        driver = RunscSandboxDriver(
            image=settings.preview_sandbox_image, runtime=settings.preview_sandbox_runtime
        )
        return await render_request(payload, driver=driver)
    except PreviewError as exc:
        # Map the render error (timeout 504, unsupported 415, bomb/oversized, E-7 500) to HTTP; the
        # core's HttpRenderTransport turns a 504 back into a PreviewError 504 for the browser.
        raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc
