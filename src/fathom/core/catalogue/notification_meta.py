"""``notification`` ORM table (ADR-031) — the in-app Notification Center ("bell") store.

One row per notification. It is the **in-app channel** of the notifications subsystem: producers
(scan-coordinator advisories, scan-health, capacity thresholds, audit events, the suitability
watcher) call :func:`fathom.core.notifications.emit`, which writes a row here; the bell UI reads
it back scope-filtered. Read-only w.r.t. the estate — a notification never triggers a write.
Reuses the catalogue ``Base`` (one metadata / one Alembic chain); portable types (PG + SQLite).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from fathom.core.catalogue.models import Base

# Category vocabulary (each notification carries exactly one; ADR-031 addendum).
CATEGORY_RECOMMENDATION = "recommendation"  # a helpful nudge ("Host X can run a larger model")
CATEGORY_PROBLEM = "problem"  # needs attention (scan failed, disk nearly full, agent offline)
CATEGORY_ACTIVITY = "activity"  # operational FYI (scan deferred/completed)
CATEGORY_SECURITY = "security"  # sensitive action (config override, remediation, sign-in)
CATEGORIES = frozenset(
    {CATEGORY_RECOMMENDATION, CATEGORY_PROBLEM, CATEGORY_ACTIVITY, CATEGORY_SECURITY}
)

# Severity controls outbound fan-out later (everything lands in the bell; only high-severity also
# goes to Email/Chat). Ordered low→high for threshold comparisons.
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
SEVERITIES = frozenset({SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL})


class Notification(Base):
    """A single in-app notification (one of CATEGORIES), optionally scoped to a host/volume."""

    __tablename__ = "notification"
    __table_args__ = (
        # Backs the bell list (newest-first) + unread-count, the common reads.
        Index("ix_notification_created_at", "created_at"),
        Index("ix_notification_read_at", "read_at"),
        # Coalesce repeats: a producer can re-emit the same logical event without flooding the bell.
        Index("ix_notification_dedup", "dedup_key"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    category: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16), default=SEVERITY_INFO)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text, default="")
    # Which subsystem raised it (e.g. "scan_coordinator", "scan_health", "capacity", "audit").
    source: Mapped[str] = mapped_column(String(64))
    # Scope: NULL host_id = estate-wide (visible to anyone who can view); otherwise scope-gated to
    # the host (and optionally a volume). App-enforced via the read query's scope predicate.
    host_id: Mapped[int | None] = mapped_column(Integer, index=True, default=None)
    volume_id: Mapped[int | None] = mapped_column(Integer, default=None)
    # Optional coalescing key; a producer re-emitting the same key updates the existing unread row
    # instead of stacking duplicates (e.g. "capacity:host=3:vol=7").
    dedup_key: Mapped[str | None] = mapped_column(String(128), default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # NULL = unread; set when the operator dismisses/reads it.
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
