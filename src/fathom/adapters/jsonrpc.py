"""Minimal JSON-RPC 2.0 framing over a WebSocket connection (ADD 04, transport only).

This is the thin, *testable-in-isolation* transport the TrueNAS adapter speaks (ADD 04 risk
mitigation: "thin JsonRpcClient + fixture-driven mappers"). It holds **no business logic** —
it correlates request ids to responses, decodes the JSON-RPC error envelope into typed
adapter errors, and reconnects the single persistent session with tenacity backoff (ADD 04,
code-quality #8). The websocket library is an **optional dependency** (extra ``truenas``);
to keep ``import fathom.adapters`` working — and ``mypy --strict`` green — without it, the
concrete websocket transport is constructed behind a lazy, guarded import and the client
itself depends only on the :class:`JsonRpcTransport` Protocol, which tests satisfy with a
fake.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from itertools import count
from typing import Any, Protocol, runtime_checkable

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from fathom.adapters.base import AdapterAuthError, AdapterUnavailableError
from fathom.logging import get_logger

_log = get_logger("fathom.adapters.jsonrpc")

# JSON-RPC error codes that mean "your credentials are bad", mapped to a fail-closed auth
# error so the caller never retries onto an insecure path (STRIDE I-2). TrueNAS middleware
# surfaces auth failures both as the standard -32000-range and as named middleware errors;
# we treat the negotiated set defensively (validate against a live box before merge — see TODO).
_AUTH_ERROR_CODES: frozenset[int] = frozenset({-32000, -32001, 401, 403})

# Reconnect policy for the persistent session (ADD 04: backoff, never per-call reconnect).
_RECONNECT_ATTEMPTS = 5
_RECONNECT_WAIT_MIN = 0.5
_RECONNECT_WAIT_MAX = 8.0


@runtime_checkable
class JsonRpcTransport(Protocol):
    """A bidirectional text frame channel (a WebSocket, or a fake in tests).

    Deliberately tiny so the JSON-RPC framing is unit-testable without a real socket and so
    the websocket dependency stays optional and injected, never imported at module top level.
    """

    async def connect(self) -> None:
        """Open the channel (idempotent; raises on unreachable endpoint)."""
        ...

    async def send(self, message: str) -> None:
        """Send one text frame."""
        ...

    async def recv(self) -> str:
        """Receive the next text frame (awaits until one arrives)."""
        ...

    async def close(self) -> None:
        """Close the channel (idempotent)."""
        ...


class JsonRpcClient:
    """An id-correlated JSON-RPC 2.0 client over a single persistent :class:`JsonRpcTransport`.

    One client owns one long-lived session for the adapter's lifetime (ADD 04). Calls are
    issued sequentially (the adapter polls, it does not pipeline), so a simple
    send-then-recv-until-matching-id loop is sufficient and keeps the framing auditable.
    """

    def __init__(
        self,
        transport: JsonRpcTransport,
        *,
        on_reconnect: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._transport = transport
        self._ids = count(1)
        self._connected = False
        # Re-establish session-level state (e.g. the adapter's api-key login) after a transport
        # reconnect. A persistent session that sits idle through a long scan is dropped by the
        # middleware AND its auth expires; reconnecting the socket alone leaves the new session
        # unauthenticated, so the retried call would fail ENOTAUTHENTICATED. Invoked once per
        # reconnect, guarded against re-entrancy so a drop *during* re-auth cannot recurse.
        self._on_reconnect = on_reconnect
        self._reauthenticating = False

    async def connect(self) -> None:
        """Open the persistent session, retrying with exponential backoff (tenacity)."""
        if self._connected:
            return
        await self._connect_with_backoff()
        self._connected = True

    @retry(
        retry=retry_if_exception_type(AdapterUnavailableError),
        stop=stop_after_attempt(_RECONNECT_ATTEMPTS),
        wait=wait_exponential(multiplier=_RECONNECT_WAIT_MIN, max=_RECONNECT_WAIT_MAX),
        reraise=True,
    )
    async def _connect_with_backoff(self) -> None:
        try:
            await self._transport.connect()
        except (OSError, AdapterUnavailableError) as exc:
            # Count-only context — no endpoint/credential material in the log (sec-arch §6).
            _log.warning("adapter transport connect failed; will back off", extra={"retry": True})
            raise AdapterUnavailableError("adapter transport unreachable") from exc

    async def call(self, method: str, params: list[Any] | dict[str, Any] | None = None) -> Any:
        """Invoke ``method`` and return its ``result``, reconnecting once on a dropped session.

        Raises:
            AdapterAuthError: On an auth-class JSON-RPC error (revoked/expired key) — never
                retried, never downgraded.
            AdapterUnavailableError: On transport failure that survives a single reconnect.
        """
        await self.connect()
        request_id = next(self._ids)
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or []}
        )
        try:
            return await self._send_and_read(payload, request_id)
        except AdapterUnavailableError:
            # One in-line reconnect for a session that dropped between calls (persistent-session
            # contract: the caller must not see a transient drop as a hard failure).
            _log.info("adapter session dropped; reconnecting once", extra={"method": method})
            self._connected = False
            await self.connect()
            # Re-authenticate the fresh session before retrying, else the retry hits
            # ENOTAUTHENTICATED on the new (unauthenticated) socket. The guard stops a drop during
            # re-auth from recursing back into another re-auth.
            if self._on_reconnect is not None and not self._reauthenticating:
                self._reauthenticating = True
                try:
                    await self._on_reconnect()
                finally:
                    self._reauthenticating = False
            return await self._send_and_read(payload, request_id)

    async def _send_and_read(self, payload: str, request_id: int) -> Any:
        try:
            await self._transport.send(payload)
            while True:
                raw = await self._transport.recv()
                message = json.loads(raw)
                if message.get("id") != request_id:
                    continue  # not our correlation id (notification / stale frame) — skip
                return self._unwrap(message)
        except (OSError, json.JSONDecodeError) as exc:
            raise AdapterUnavailableError("adapter transport read/write failed") from exc

    @staticmethod
    def _unwrap(message: dict[str, Any]) -> Any:
        """Return ``result`` or raise the typed error for a JSON-RPC error envelope."""
        error = message.get("error")
        if error is None:
            return message.get("result")
        code = error.get("code")
        msg = error.get("message", "JSON-RPC error")
        if isinstance(code, int) and code in _AUTH_ERROR_CODES:
            # Fail closed: revoked/expired/forbidden — surface for key rotation (ADR-010).
            raise AdapterAuthError(f"adapter authentication failed (code {code})")
        raise AdapterUnavailableError(f"adapter call failed: {msg} (code {code})")

    async def close(self) -> None:
        """Close the persistent session (idempotent)."""
        if not self._connected:
            return
        self._connected = False
        try:
            await self._transport.close()
        except OSError:  # pragma: no cover — best-effort teardown
            _log.warning("adapter transport close failed", extra={"swallowed": True})


def build_websocket_transport(
    endpoint: str, *, verify_ssl: bool, api_key: str | None
) -> JsonRpcTransport:
    """Construct the production WebSocket transport (lazy-imports the optional ``websockets``).

    Importing ``websockets`` here — not at module top level — keeps ``fathom.adapters``
    importable (and ``mypy --strict`` collection green) without the ``truenas`` extra
    installed (ADD 04 optional-dependency risk). Raises a clear, typed error if the extra is
    missing so the failure is actionable, not an opaque ``ImportError``.
    """
    try:
        from fathom.adapters._ws import WebSocketTransport
    except ImportError as exc:  # pragma: no cover — exercised only without the extra
        raise AdapterUnavailableError(
            "the 'truenas' extra (websockets) is not installed; "
            "install fathom[truenas] to use the WebSocket transport"
        ) from exc
    return WebSocketTransport(endpoint, verify_ssl=verify_ssl, api_key=api_key)
