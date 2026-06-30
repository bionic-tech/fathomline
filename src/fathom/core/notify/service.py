"""Emit-and-dispatch (ADR-039) — write the bell row, then fan out to outbound channels.

The one call a producer (e.g. the proactive watcher, ADR-040) makes to both record a notification
in the in-app bell and push it to the configured Email/Chat channels. The bell write is the source
of truth; outbound is best-effort on top (a channel failure never rolls back the bell row).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core import notifications
from fathom.core.catalogue.notification_meta import Notification
from fathom.core.notify.channels import (
    NotifyTransport,
    OutboundNote,
    SecretProvider,
    dispatch_outbound,
)
from fathom.core.settings import Settings


async def emit_and_dispatch(
    session: AsyncSession,
    settings: Settings,
    secret_provider: SecretProvider,
    *,
    category: str,
    title: str,
    source: str,
    body: str = "",
    severity: str = "info",
    host_id: int | None = None,
    volume_id: int | None = None,
    dedup_key: str | None = None,
    transport: NotifyTransport | None = None,
    now: datetime | None = None,
) -> tuple[Notification, list[str]]:
    """Emit a bell notification and fan it out; return the row + the channels delivered to."""
    note = await notifications.emit(
        session,
        category=category,
        title=title,
        source=source,
        body=body,
        severity=severity,
        host_id=host_id,
        volume_id=volume_id,
        dedup_key=dedup_key,
        now=now,
    )
    delivered = await dispatch_outbound(
        settings,
        secret_provider,
        OutboundNote(
            category=category, severity=severity, title=title, body=body, source=source
        ),
        transport=transport,
    )
    return note, delivered
