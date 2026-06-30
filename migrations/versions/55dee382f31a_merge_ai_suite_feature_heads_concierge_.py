"""merge ai-suite feature heads (concierge + scan-coordinator + notifications)

Revision ID: 55dee382f31a
Revises: c1a2b3d4e5f6, d5e6f7a8b9c0, e1f2a3b4c5d6
Create Date: 2026-06-19 12:16:05.956884

A no-op **merge revision**: the AI-suite integration branch brings together three independent
feature migrations that each chained directly off the master head ``b4d7e9f2a1c5`` (concierge
``fs_entry_embedding``, the scan-coordinator ``scan_lease``, and the notification-center store).
They touch disjoint tables, so there is nothing to reconcile — this revision merely collapses the
three Alembic heads back into one linear chain so ``alembic upgrade head`` is unambiguous.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "55dee382f31a"
down_revision: str | Sequence[str] | None = (
    "c1a2b3d4e5f6",
    "d5e6f7a8b9c0",
    "e1f2a3b4c5d6",
)
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """No schema change — purely a head merge."""


def downgrade() -> None:
    """No schema change — purely a head merge."""
