"""WebSocketTransport reconnect-hygiene tests (ADD 04; the TrueNAS idle-drop bug).

A middleware-closed (idle) session must leave the transport in a state where the next
``connect()`` actually re-opens. The bug: ``send``/``recv`` raised but never cleared ``_conn``,
so ``connect()``'s ``if self._conn is not None: return`` short-circuited and the reconnect-retry
kept hitting the dead socket — a drop loop that fail-closed the full-bit resync guard forever.
"""

from __future__ import annotations

import pytest

from fathom.adapters._ws import WebSocketTransport
from fathom.adapters.base import AdapterUnavailableError


class _DeadConn:
    """A connection object whose every I/O raises, as a middleware-closed socket would."""

    async def send(self, _message: str) -> None:
        raise OSError("connection closed")

    async def recv(self) -> str:
        raise OSError("connection closed")

    async def close(self) -> None:  # pragma: no cover - not exercised here
        pass


def _transport() -> WebSocketTransport:
    return WebSocketTransport(
        "unix:///run/middleware/middlewared.sock", verify_ssl=True, api_key=None
    )


async def test_send_failure_clears_conn_so_connect_reopens() -> None:
    transport = _transport()
    transport._conn = _DeadConn()  # type: ignore[assignment]  # simulate a live-then-dropped socket
    with pytest.raises(AdapterUnavailableError):
        await transport.send("ping")
    # Cleared → connect()'s "already connected?" guard no longer reuses the dead socket.
    assert transport._conn is None


async def test_recv_failure_clears_conn() -> None:
    transport = _transport()
    transport._conn = _DeadConn()  # type: ignore[assignment]
    with pytest.raises(AdapterUnavailableError):
        await transport.recv()
    assert transport._conn is None


async def test_send_on_unconnected_raises() -> None:
    transport = _transport()
    with pytest.raises(AdapterUnavailableError):
        await transport.send("ping")
