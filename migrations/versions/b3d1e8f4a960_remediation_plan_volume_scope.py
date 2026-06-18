"""remediation_plan.volume_id (re-assert volume scope at act time)

Revision ID: b3d1e8f4a960
Revises: a1c9f3b6d720
Create Date: 2026-06-08 14:10:00.000000

Adversarial-review fix for the Organize MOVE apply path (ADR-023): the persisted plan recorded
only ``host_id``, so the dry-run/execute routes could only re-assert *host* scope — a build that a
volume-scoped grant authorised was re-checked too coarsely at act time (and a volume-scoped
remediator was locked out of running their own plan). This adds a nullable ``volume_id`` to
``remediation_plan`` so an Organize plan (confined to one volume) carries the volume it was
authorised against; the act-time routes re-assert ``check_target(host_id, volume_id)``.

``NULL`` for every existing row and every dedup plan (which may legitimately span volumes of one
host and re-asserts host scope, unchanged), so the change is behaviour-preserving. Chained linearly
off ``a1c9f3b6d720`` (organize MOVE plan columns).

Portability: ``remediation_plan`` is a plain table on both PostgreSQL and SQLite; a nullable
``ADD COLUMN`` is a catalogue-only change on both.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3d1e8f4a960"
down_revision: str | None = "a1c9f3b6d720"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "remediation_plan",
        sa.Column("volume_id", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("remediation_plan", "volume_id")
