"""organize-apply MOVE plan columns (move_root + dest_rel)

Revision ID: a1c9f3b6d720
Revises: f6c4d8a1b2e7
Create Date: 2026-06-08 12:30:00.000000

ADR-023 (reversible MOVE/RENAME) gives the Organize feature a gated *apply*: an approved
suggestion becomes a remediation plan whose items relocate within one operator-approved root.
Two nullable columns carry that, additive to the existing remediation write-path schema:

* ``remediation_plan.move_root`` — the trusted anchor a MOVE plan may relocate within. The actor
  opens it with ``O_NOFOLLOW`` and refuses any destination not reached from it via non-symlink
  components (the path-firewall anchor; ADR-023, security review).
* ``remediation_plan_item.dest_rel`` — the per-item destination RELATIVE to ``move_root``, already
  server-clamped to the root at build time (the model proposes, the server decides).

Both are ``NULL`` for every existing row and every dedup plan (quarantine/hardlink/delete never
move), so the change is behaviour-preserving. Chained linearly off the current head
``f6c4d8a1b2e7`` (fs_entry dev identity) — one head, no branch.

Portability:

* **PostgreSQL** — ``remediation_plan`` / ``remediation_plan_item`` are plain tables; a nullable
  ``ADD COLUMN`` is an instant catalogue-only change (no rewrite, no default backfill).
* **SQLite** (dev/test) — a nullable ``ADD COLUMN`` with no constraint change is supported
  directly; no table-copy batch block is needed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1c9f3b6d720"
down_revision: str | None = "f6c4d8a1b2e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "remediation_plan",
        sa.Column("move_root", sa.String(length=4096), nullable=True),
    )
    op.add_column(
        "remediation_plan_item",
        sa.Column("dest_rel", sa.String(length=4096), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("remediation_plan_item", "dest_rel")
    op.drop_column("remediation_plan", "move_root")
