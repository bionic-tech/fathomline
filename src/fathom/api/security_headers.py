"""Security-headers + CSP middleware for the api (frontend ADD §12, ADD 03 §2.1).

A strict Content-Security-Policy with **no ``unsafe-inline`` and no ``unsafe-eval``** (frontend
ADD §12, security ADD §2) plus the standard hardening headers. The policy is same-origin by
default — the SPA is served from the same container as ``/api/v1`` (frontend ADD §15) so it
needs no cross-origin ``connect-src``. ECharts/Tailwind are built with hashed assets and no
inline ``<script>``/``<style>`` (spec risk: naive ECharts/Tailwind can break under a strict
CSP — the Vite build avoids inline), so the strict policy holds.

The headers attach to every response, including the JSON API surface; they are inert for API
clients and protective for the browser. This middleware never touches authentication — the
agent mTLS ingest boundary stays ``FingerprintDep`` (ADD 03 §3).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# No unsafe-inline / unsafe-eval anywhere (frontend ADD §12). default-src 'self' keeps every
# fetch/asset same-origin; img-src allows data: for ECharts-rendered raster/thumbnails; the
# preview pane renders *derived* artifacts only (ADR-014), never raw bytes.
#
# Brand fonts (Fathomline): the Sora/Inter/JetBrains-Mono webfonts are loaded from Google Fonts, so
# style-src additionally allows the stylesheet origin (fonts.googleapis.com) and font-src the font
# file origin (fonts.gstatic.com). These are the ONLY third-party origins; everything else stays
# 'self'. If you prefer a strictly self-only CSP, self-host the fonts and drop both origins (the SPA
# falls back to system fonts regardless — see assets/brand/brand-tokens.css).
_CSP = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'self'",
        "script-src 'self'",
        "style-src 'self' https://fonts.googleapis.com",
        "img-src 'self' data:",
        "font-src 'self' https://fonts.gstatic.com",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "object-src 'none'",
    )
)

_STATIC_HEADERS: dict[str, str] = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach the strict CSP + hardening headers to every response (frontend ADD §12)."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for header, value in _STATIC_HEADERS.items():
            response.headers.setdefault(header, value)
        return response
