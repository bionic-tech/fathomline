"""Static SPA serving + history fallback for the built viewer (frontend ADD §15, ADR-012).

The built React SPA (``src/fathom/web/dist``) is served by the **same** api container, same
origin as ``/api/v1`` — no separate web server (ADR-012 supply chain: the dist is built in a
node stage and COPYed into the image, never built at runtime). Serving is guarded entirely
behind ``settings.web_dist``: when it is unset the api exposes only ``/api/v1`` + ``/healthz``
and this module mounts nothing (dev / fronted-elsewhere).

SPA history fallback: unknown non-API GET paths return ``index.html`` so client-side routes
(``/dashboard``, ``/explore`` …) deep-link correctly, while ``/api`` and ``/healthz`` stay
owned by their routers. Path traversal is impossible — the fallback only ever serves the
fixed ``index.html``; real asset requests go through Starlette's :class:`StaticFiles`, which
resolves and bounds paths inside ``dist`` itself.
"""

from __future__ import annotations

import anyio
from fastapi import FastAPI, Request, status
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

# Path prefixes the SPA fallback must never swallow — they belong to the API/meta routers.
_RESERVED_PREFIXES = ("/api", "/healthz", "/docs", "/redoc", "/openapi.json")


def _resolve_asset(dist: anyio.Path, full_path: str) -> anyio.Path | None:
    """Return the bounded real file for ``full_path`` inside ``dist``, or ``None``.

    Resolves symlinks/``..`` and confirms the result is contained in ``dist`` so the fallback
    can never serve a file outside the build directory (path-traversal guard). Runs on a
    worker thread (blocking ``stat``), keeping the event loop free (standards/18 §7).
    """
    from pathlib import Path

    base = Path(dist).resolve()
    candidate = (base / full_path).resolve()
    if candidate.is_file() and base in candidate.parents:
        return anyio.Path(candidate)
    return None


def mount_spa(app: FastAPI, dist: anyio.Path) -> None:
    """Mount the built SPA from ``dist`` with a same-origin history fallback.

    ``dist`` must contain an ``index.html`` and a hashed-asset directory. Hashed assets are
    served by :class:`StaticFiles` (which bounds paths inside ``dist``); any other GET that is
    not an API/meta route falls back to ``index.html`` so client-side routing works on reload.

    Mount-time existence checks are synchronous (the app is being built, no event loop yet);
    per-request asset resolution is delegated to a worker thread (``_resolve_asset``).
    """
    from pathlib import Path

    base = Path(dist)
    index = base / "index.html"
    if not index.is_file():
        raise RuntimeError(f"FATHOM_WEB_DIST has no index.html: {base}")
    index_path = anyio.Path(index)

    # Serve hashed build assets directly (immutable, content-addressed) under /assets.
    assets = base / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="spa-assets")

    @app.get("/", include_in_schema=False)
    async def spa_root() -> FileResponse:
        return FileResponse(index_path)

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str, request: Request) -> Response:
        # Never shadow the API/meta surface — those routers already matched if applicable;
        # an unmatched /api path is a genuine 404, not an SPA route.
        normalised = "/" + full_path
        if any(normalised == p or normalised.startswith(p + "/") for p in _RESERVED_PREFIXES):
            return JSONResponse({"detail": "Not Found"}, status_code=status.HTTP_404_NOT_FOUND)
        # Serve a real built file if it exists; otherwise fall back to index.html (SPA route).
        asset = await anyio.to_thread.run_sync(_resolve_asset, anyio.Path(base), full_path)
        return FileResponse(asset if asset is not None else index_path)
