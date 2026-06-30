"""Outbound channel transports + dispatch (ADR-039).

A small, dependency-light fan-out: chat webhooks go over httpx; email goes over the stdlib
``smtplib`` in a worker thread (no new async-SMTP dependency). The transport is an injectable
:class:`NotifyTransport` so tests drive dispatch without touching the network. ``dispatch_outbound``
applies the category + severity policy and sends to each enabled channel, swallowing per-channel
errors; ``send_test`` ignores the policy (a connectivity check) and reports each channel's outcome.
"""

from __future__ import annotations

import asyncio
import smtplib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

import httpx

from fathom.core.catalogue.notification_meta import (
    SEVERITY_CRITICAL,
    SEVERITY_INFO,
    SEVERITY_WARNING,
)
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.core.notify")

# Severity ordering for the "minimum severity" threshold (low → high).
_SEVERITY_RANK = {SEVERITY_INFO: 0, SEVERITY_WARNING: 1, SEVERITY_CRITICAL: 2}

SecretProvider = Callable[[str], str]


@dataclass(frozen=True)
class OutboundNote:
    """The minimal note an outbound channel renders (decoupled from the ORM row)."""

    category: str
    severity: str
    title: str
    body: str
    source: str


@dataclass(frozen=True)
class ChannelResult:
    """The outcome of one channel send (for the test endpoint + observability)."""

    channel: str
    ok: bool
    detail: str = ""


class NotifyTransport(Protocol):
    """The injectable I/O seam: a chat webhook POST and an SMTP send."""

    async def post_json(
        self, url: str, payload: dict[str, object], *, timeout_seconds: float
    ) -> None: ...

    async def send_email(
        self,
        *,
        host: str,
        port: int,
        use_tls: bool,
        username: str | None,
        password: str | None,
        sender: str,
        recipients: Sequence[str],
        subject: str,
        body: str,
        timeout_seconds: float,
    ) -> None: ...


class HttpxSmtpTransport:
    """The real transport: httpx for chat webhooks, stdlib smtplib (in a thread) for email."""

    async def post_json(
        self, url: str, payload: dict[str, object], *, timeout_seconds: float
    ) -> None:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()

    async def send_email(
        self,
        *,
        host: str,
        port: int,
        use_tls: bool,
        username: str | None,
        password: str | None,
        sender: str,
        recipients: Sequence[str],
        subject: str,
        body: str,
        timeout_seconds: float,
    ) -> None:
        def _send() -> None:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg.set_content(body)
            with smtplib.SMTP(host, port, timeout=timeout_seconds) as smtp:
                if use_tls:
                    smtp.starttls()
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(msg)

        await asyncio.to_thread(_send)


def should_dispatch(settings: Settings, *, category: str, severity: str) -> bool:
    """Return whether a note qualifies for outbound fan-out (category + severity policy)."""
    if severity not in _SEVERITY_RANK:
        return False
    if category not in settings.notify_outbound_categories:
        return False
    min_rank = _SEVERITY_RANK.get(settings.notify_min_severity, _SEVERITY_RANK[SEVERITY_WARNING])
    return _SEVERITY_RANK[severity] >= min_rank


def _email_configured(settings: Settings) -> bool:
    return bool(
        settings.notify_email_smtp_host and settings.notify_email_from and settings.notify_email_to
    )


def _subject(note: OutboundNote) -> str:
    return f"[Fathomline · {note.severity}] {note.title}"


def _chat_text(note: OutboundNote) -> str:
    lines = [f"[{note.severity.upper()}] {note.title}"]
    if note.body:
        lines.append(note.body)
    lines.append(f"— {note.source}")
    return "\n".join(lines)


async def _send_email(
    settings: Settings,
    secret_provider: SecretProvider,
    note: OutboundNote,
    transport: NotifyTransport,
    timeout_seconds: float,
) -> None:
    password = (
        secret_provider(settings.notify_email_password_ref)
        if settings.notify_email_password_ref
        else None
    )
    assert settings.notify_email_smtp_host is not None  # noqa: S101 — guarded by _email_configured
    assert settings.notify_email_from is not None  # noqa: S101
    body = note.body or note.title
    await transport.send_email(
        host=settings.notify_email_smtp_host,
        port=settings.notify_email_smtp_port,
        use_tls=settings.notify_email_use_tls,
        username=settings.notify_email_username,
        password=password,
        sender=settings.notify_email_from,
        recipients=settings.notify_email_to,
        subject=_subject(note),
        body=f"{body}\n\n— {note.source}",
        timeout_seconds=timeout_seconds,
    )


async def _send_chat(
    settings: Settings,
    secret_provider: SecretProvider,
    note: OutboundNote,
    transport: NotifyTransport,
    timeout_seconds: float,
) -> None:
    assert settings.notify_chat_webhook_ref is not None  # noqa: S101 — guarded by caller
    secret = secret_provider(settings.notify_chat_webhook_ref)
    if not secret:
        raise ValueError("chat webhook reference did not resolve")
    kind = settings.notify_chat_kind.lower()
    text = _chat_text(note)
    if kind == "discord":
        await transport.post_json(secret, {"content": text}, timeout_seconds=timeout_seconds)
    elif kind == "slack":
        await transport.post_json(secret, {"text": text}, timeout_seconds=timeout_seconds)
    elif kind == "telegram":
        chat_id = settings.notify_chat_telegram_chat_id
        if not chat_id:
            raise ValueError("telegram chat requires notify_chat_telegram_chat_id")
        # The secret is the bot token; build the sendMessage API URL.
        url = f"https://api.telegram.org/bot{secret}/sendMessage"
        await transport.post_json(
            url, {"chat_id": chat_id, "text": text}, timeout_seconds=timeout_seconds
        )
    else:
        raise ValueError(f"unknown chat kind {settings.notify_chat_kind!r}")


def _chat_label(settings: Settings) -> str:
    return f"chat:{settings.notify_chat_kind.lower()}"


async def dispatch_outbound(
    settings: Settings,
    secret_provider: SecretProvider,
    note: OutboundNote,
    *,
    transport: NotifyTransport | None = None,
) -> list[str]:
    """Send ``note`` to each enabled, qualifying channel; return the channels delivered to.

    Applies the category + severity policy (:func:`should_dispatch`) and the master notifications
    gate. Best-effort: a channel that raises is logged and skipped — never propagated.
    """
    if not settings.notifications_enabled:
        return []
    if not should_dispatch(settings, category=note.category, severity=note.severity):
        return []
    tx = transport or HttpxSmtpTransport()
    timeout = settings.notify_send_timeout_seconds
    delivered: list[str] = []
    if settings.notify_email_enabled and _email_configured(settings):
        try:
            await _send_email(settings, secret_provider, note, tx, timeout)
            delivered.append("email")
        except Exception:
            _log.exception("email notification send failed")
    if settings.notify_chat_enabled and settings.notify_chat_webhook_ref:
        try:
            await _send_chat(settings, secret_provider, note, tx, timeout)
            delivered.append(_chat_label(settings))
        except Exception:
            _log.exception("chat notification send failed")
    return delivered


async def send_test(
    settings: Settings,
    secret_provider: SecretProvider,
    *,
    transport: NotifyTransport | None = None,
) -> list[ChannelResult]:
    """Send a connectivity test to every ENABLED channel, ignoring the category/severity policy.

    Returns one :class:`ChannelResult` per enabled channel (ok + detail) so the operator can see
    exactly which channel works and why one failed. An empty list means no channel is enabled.
    """
    tx = transport or HttpxSmtpTransport()
    timeout = settings.notify_send_timeout_seconds
    note = OutboundNote(
        category="activity",
        severity="info",
        title="Fathomline test notification",
        body="If you can read this, the channel is configured correctly.",
        source="settings",
    )
    results: list[ChannelResult] = []
    if settings.notify_email_enabled:
        if not _email_configured(settings):
            results.append(ChannelResult("email", False, "missing smtp host / from / recipients"))
        else:
            try:
                await _send_email(settings, secret_provider, note, tx, timeout)
                results.append(ChannelResult("email", True, "sent"))
            except Exception as exc:
                results.append(ChannelResult("email", False, str(exc)))
    if settings.notify_chat_enabled:
        if not settings.notify_chat_webhook_ref:
            results.append(ChannelResult(_chat_label(settings), False, "no webhook reference"))
        else:
            try:
                await _send_chat(settings, secret_provider, note, tx, timeout)
                results.append(ChannelResult(_chat_label(settings), True, "sent"))
            except Exception as exc:
                results.append(ChannelResult(_chat_label(settings), False, str(exc)))
    return results
