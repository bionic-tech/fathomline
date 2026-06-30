"""``scan_lease`` ORM table (ADR-036) — the scan concurrency coordinator's ledger.

One row per lease decision. A GRANT inserts an ``active`` row (released when the agent reports its
run, or auto-expired after a TTL if the agent dies). A DEFER inserts a ``deferred`` row that doubles
as the operator-facing **advisory** — it records *why* (reason + the blocking host) and *when* to
retry — since the notifications subsystem (ADR-031) is not built yet. Reuses the catalogue ``Base``
so one metadata / one Alembic chain governs the schema; types are portable (PostgreSQL + SQLite).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from fathom.core.catalogue.models import Base

# Lease status vocabulary.
LEASE_ACTIVE = "active"
LEASE_RELEASED = "released"
LEASE_EXPIRED = "expired"
LEASE_DEFERRED = "deferred"


class ScanLease(Base):
    """A scan-lease decision: an active/released/expired lease, or a deferred-scan advisory."""

    __tablename__ = "scan_lease"
    __table_args__ = (
        # Backs the "count active heavy leases" check (the core of the grant/defer decision).
        Index("ix_scan_lease_status_heavy", "status", "is_heavy"),
        # Backs the advisory read surface (newest-first). (host_id is indexed via the column below.)
        Index("ix_scan_lease_granted_at", "granted_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id"), index=True)
    is_heavy: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    # active | released | expired | deferred (see the LEASE_* constants).
    status: Mapped[str] = mapped_column(String(16))
    # For a deferred row (the advisory): why it was deferred, which host held the lease, and the
    # advised retry delay. Null on a granted lease.
    reason: Mapped[str | None] = mapped_column(String(255), default=None)
    blocking_host_id: Mapped[int | None] = mapped_column(BigInteger, default=None)
    retry_after_seconds: Mapped[int | None] = mapped_column(Integer, default=None)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # For an active lease: when it auto-expires (the crash safety net). Null on a deferred row.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
