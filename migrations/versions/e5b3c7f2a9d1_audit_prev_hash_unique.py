"""audit prev_hash unique (chain-fork hardening)

Revision ID: e5b3c7f2a9d1
Revises: d4a7c2e91b53
Create Date: 2026-06-06 13:00:00.000000

Harden the persisted remediation audit chain against a **fork under concurrent appends**
(security-review MEDIUM; ADD 03 §8). The chain head is resumed from the last row, so two writers
that read the same head and both append produce two sibling rows carrying the *same* ``prev_hash``
— a forked chain. Promoting ``prev_hash`` from a plain index to a UNIQUE constraint makes the DB
the single arbiter: only one row may point at any given predecessor, so the losing sibling's
INSERT fails and that writer must retry against the new head (mirrors the ``used_nonce`` UNIQUE
pattern, T-3).

Chained linearly off the current head ``d4a7c2e91b53`` (preview_cache_meta) — one head, no branch
(``uv run alembic heads`` reported ``d4a7c2e91b53`` as the sole head before this revision).

Portable: SQLite cannot ``ALTER TABLE ... ADD CONSTRAINT``, so this uses Alembic batch mode
(``recreate='always'``) which table-copies under SQLite and emits a plain ``ALTER`` on PostgreSQL.
The pre-existing ``ix_remediation_audit_prev_hash`` index is dropped first (the UNIQUE constraint
subsumes it). No data backfill: any deployment that already forked must be reconciled out-of-band
before applying — a duplicate ``prev_hash`` will make this migration fail loudly (fail-closed),
which is the intended signal.

Append-only discipline is unchanged: the API DB role still gets SELECT/INSERT but not
UPDATE/DELETE on ``remediation_audit`` (managed at the role layer, documented in the runbook).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "e5b3c7f2a9d1"
down_revision: str | None = "d4a7c2e91b53"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop the plain index outside batch mode (portable on both backends).
    op.drop_index("ix_remediation_audit_prev_hash", table_name="remediation_audit")
    # Add the UNIQUE constraint via batch mode so SQLite (no ALTER ADD CONSTRAINT) is supported.
    with op.batch_alter_table("remediation_audit", recreate="always") as batch:
        batch.create_unique_constraint("uq_remediation_audit_prev_hash", ["prev_hash"])


def downgrade() -> None:
    with op.batch_alter_table("remediation_audit", recreate="always") as batch:
        batch.drop_constraint("uq_remediation_audit_prev_hash", type_="unique")
    op.create_index(
        "ix_remediation_audit_prev_hash",
        "remediation_audit",
        ["prev_hash"],
        unique=False,
    )
