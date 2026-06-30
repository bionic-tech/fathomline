"""host facts — agent-reported hardware for the suitability engine (ADR-037)

Revision ID: b8e4c2f6a1d9
Revises: a7c3e9f1b2d4
Create Date: 2026-06-19 14:00:00.000000

Adds a nullable JSON ``facts`` column to ``host`` holding the hardware an agent probes (CPU cores +
model, RAM bytes, GPU name + VRAM, arch). It feeds the suitability / traffic-light engine (ADR-037).
Behaviour-preserving: null for a pre-facts agent; the column is only written when an agent reports
facts and is never overwritten with null. Portable DDL (PostgreSQL + SQLite).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b8e4c2f6a1d9"
down_revision: str | None = "a7c3e9f1b2d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("host", sa.Column("facts", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("host", "facts")
