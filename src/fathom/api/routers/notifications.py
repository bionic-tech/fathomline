"""Notification Center router (ADR-031) — the in-app "bell" read/dismiss surface.

All routes are **read-class** and gated by ``VIEW_METADATA`` + scope, default-OFF behind
``notifications_enabled`` (the SPA hides the bell when off). Listing + the unread badge are
scope-filtered (estate-wide notifications are visible to anyone who can view; host-scoped ones only
to principals in scope). Mark-read flips ``read_at`` on the principal's own visible notifications —
a benign acknowledgement, not an estate write.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from fathom.api.auth_deps import require
from fathom.api.deps import SecretProviderDep, SessionDep, SettingsDep
from fathom.api.schemas import (
    MarkReadRequest,
    MarkReadResult,
    NotificationListOut,
    NotificationOut,
    NotifyChannelResult,
    NotifyTestResult,
    UnreadCountOut,
)
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import notifications
from fathom.core.catalogue.notification_meta import CATEGORIES, Notification
from fathom.core.notify import send_test
from fathom.core.notify.channels import NotifyTransport

router = APIRouter(prefix="/api/v1", tags=["notifications"])

ViewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]
# Channel config is admin-only (it lives in the runtime settings store), so the connectivity test
# rides MANAGE_SETTINGS, not the read-class VIEW_METADATA the bell uses.
ManageSettingsDep = Annotated[ScopeFilter, Depends(require(Capability.MANAGE_SETTINGS))]


def _gate(settings: SettingsDep) -> None:
    if not settings.notifications_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="notifications are disabled (notifications_enabled=False)",
        )


def _to_out(n: Notification) -> NotificationOut:
    return NotificationOut(
        id=n.id,
        category=n.category,
        severity=n.severity,
        title=n.title,
        body=n.body,
        source=n.source,
        host_id=n.host_id,
        volume_id=n.volume_id,
        created_at=n.created_at,
        read=n.read_at is not None,
    )


@router.get("/notifications", response_model=NotificationListOut)
async def list_notifications(
    session: SessionDep,
    settings: SettingsDep,
    scope: ViewScopeDep,
    unread_only: Annotated[bool, Query()] = False,
    category: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> NotificationListOut:
    """List notifications for the bell (newest first, scope-filtered) + the unread count."""
    _gate(settings)
    if category is not None and category not in CATEGORIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unknown category"
        )
    rows = await notifications.list_notifications(
        session, scope=scope, unread_only=unread_only, category=category, limit=limit
    )
    count = await notifications.unread_count(session, scope=scope)
    return NotificationListOut(items=[_to_out(n) for n in rows], unread_count=count)


@router.get("/notifications/unread-count", response_model=UnreadCountOut)
async def get_unread_count(
    session: SessionDep, settings: SettingsDep, scope: ViewScopeDep
) -> UnreadCountOut:
    """The cheap poll behind the bell badge (scope-filtered unread count)."""
    _gate(settings)
    return UnreadCountOut(unread_count=await notifications.unread_count(session, scope=scope))


@router.post("/notifications/mark-read", response_model=MarkReadResult)
async def mark_read(
    body: MarkReadRequest, session: SessionDep, settings: SettingsDep, scope: ViewScopeDep
) -> MarkReadResult:
    """Mark specific (in-scope, unread) notifications read."""
    _gate(settings)
    marked = await notifications.mark_read(session, ids=body.ids, scope=scope)
    return MarkReadResult(marked=marked)


@router.post("/notifications/mark-all-read", response_model=MarkReadResult)
async def mark_all_read(
    session: SessionDep, settings: SettingsDep, scope: ViewScopeDep
) -> MarkReadResult:
    """Mark every in-scope unread notification read."""
    _gate(settings)
    marked = await notifications.mark_all_read(session, scope=scope)
    return MarkReadResult(marked=marked)


@router.post("/notifications/test", response_model=NotifyTestResult)
async def test_channels(
    request: Request,
    settings: SettingsDep,
    secret_provider: SecretProviderDep,
    _scope: ManageSettingsDep,
) -> NotifyTestResult:
    """Send a connectivity test to every ENABLED outbound channel (admin-only); report each outcome.

    Ignores the category/severity policy (it is a configuration check, not a real alert) but honours
    the per-channel enable flags. The secret references (SMTP password, chat webhook/bot token)
    resolve via the in-app secret store (ADR-038). The transport is injectable via
    ``app.state.notify_transport`` for tests; production uses the real httpx/SMTP transport.

    Deliberately NOT gated on ``notifications_enabled``: an admin verifies channel config *before*
    flipping the master gate on. It only ever contacts channels the admin explicitly enabled.
    """
    transport: NotifyTransport | None = getattr(request.app.state, "notify_transport", None)
    results = await send_test(settings, secret_provider, transport=transport)
    return NotifyTestResult(
        results=[
            NotifyChannelResult(channel=r.channel, ok=r.ok, detail=r.detail) for r in results
        ]
    )
