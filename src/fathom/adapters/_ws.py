"""Concrete WebSocket :class:`~fathom.adapters.jsonrpc.JsonRpcTransport` (optional ``truenas``).

Isolated in its own module so the optional ``websockets`` import is reached **only** through
the lazy :func:`~fathom.adapters.jsonrpc.build_websocket_transport` factory. Importing
``fathom.adapters`` (or its base/registry/generic modules) never touches this file, so the
package — and ``mypy --strict`` collection — works without the ``truenas`` extra installed
(ADD 04 optional-dependency risk).

``verify_ssl=True`` is the default everywhere; the only way an unverified context reaches the
``wss`` handshake is the explicit, loud lab profile validated in
:class:`~fathom.adapters.config.AdapterConfig` (sec-arch §6, STRIDE S-4).
"""

from __future__ import annotations

import ssl
from typing import Any
from urllib.parse import urlparse

import websockets

from fathom.adapters.base import AdapterUnavailableError
from fathom.logging import get_logger

_log = get_logger("fathom.adapters.ws")

# The middleware's versioned JSON-RPC websocket route. ``current`` is the stable alias TrueNAS
# keeps pointed at the live API version, so the on-box socket path need not pin a version.
_MIDDLEWARE_WS_ROUTE = "ws://localhost/api/current"


class WebSocketTransport:
    """A persistent client WebSocket speaking text frames (one session per adapter lifetime)."""

    def __init__(self, endpoint: str, *, verify_ssl: bool, api_key: str | None) -> None:
        self._endpoint = endpoint
        self._verify_ssl = verify_ssl
        # Held only for the duration of the session; never logged (count-only, sec-arch §6).
        self._api_key = api_key
        self._conn: Any | None = None

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self._endpoint.startswith("wss://"):
            return None
        ctx = ssl.create_default_context()
        if not self._verify_ssl:  # only reachable behind the validated lab profile
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _log.warning("adapter TLS verification disabled — lab profile only")
        return ctx

    async def connect(self) -> None:
        if self._conn is not None:
            return
        try:
            if urlparse(self._endpoint).scheme == "unix":
                # On-box: speak the JSON-RPC websocket over the middleware's local unix socket
                # (no TLS, no network egress). The endpoint's path is the socket; the ws route is
                # the stable ``/api/current`` alias (ADD 04, on-box adapter; ADR-025 scan-fix).
                self._conn = await websockets.unix_connect(
                    urlparse(self._endpoint).path,
                    _MIDDLEWARE_WS_ROUTE,
                    open_timeout=10,
                    ping_interval=20,
                )
            else:
                self._conn = await websockets.connect(
                    self._endpoint,
                    ssl=self._ssl_context(),
                    open_timeout=10,
                    ping_interval=20,
                )
        except (OSError, websockets.WebSocketException) as exc:
            raise AdapterUnavailableError("websocket connect failed") from exc

    async def send(self, message: str) -> None:
        if self._conn is None:
            raise AdapterUnavailableError("websocket not connected")
        try:
            await self._conn.send(message)
        except (OSError, websockets.WebSocketException) as exc:
            # Drop the dead connection so the next connect() re-opens it. Without this, a
            # middleware-closed (idle) session leaves a non-None but unusable ``_conn``, so
            # connect() short-circuits and the reconnect-retry keeps hitting the dead socket.
            self._conn = None
            raise AdapterUnavailableError("websocket send failed") from exc

    async def recv(self) -> str:
        if self._conn is None:
            raise AdapterUnavailableError("websocket not connected")
        try:
            frame = await self._conn.recv()
        except (OSError, websockets.WebSocketException) as exc:
            self._conn = None  # see send(): clear so the next connect() actually reconnects
            raise AdapterUnavailableError("websocket recv failed") from exc
        return frame if isinstance(frame, str) else frame.decode("utf-8", errors="replace")

    async def close(self) -> None:
        if self._conn is None:
            return
        conn, self._conn = self._conn, None
        await conn.close()
