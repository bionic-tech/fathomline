"""Outbound notification fan-out (ADR-039) — Email + Chat on top of the in-app bell (ADR-031).

Every notification lands in the in-app bell (``core.notifications.emit``); this package is the
EXTRA fan-out to operator-configured global channels (one Email/SMTP + one Chat webhook —
Discord/Slack/Telegram). Dispatch is best-effort and fail-soft: a channel that errors or times out
is logged and skipped, never breaking the producer or losing the (already-written) bell row.
"""

from __future__ import annotations

from fathom.core.notify.channels import (
    ChannelResult,
    HttpxSmtpTransport,
    NotifyTransport,
    OutboundNote,
    dispatch_outbound,
    send_test,
    should_dispatch,
)
from fathom.core.notify.service import emit_and_dispatch

__all__ = [
    "ChannelResult",
    "HttpxSmtpTransport",
    "NotifyTransport",
    "OutboundNote",
    "dispatch_outbound",
    "emit_and_dispatch",
    "send_test",
    "should_dispatch",
]
