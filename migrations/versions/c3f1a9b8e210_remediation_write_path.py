"""remediation write path

Revision ID: c3f1a9b8e210
Revises: 9e41f1184d8a
Create Date: 2026-06-06 09:30:00.000000

Persisted remediation write-path tables (ADR-011, remediation-enable; DEFAULTS
data_model_changes) chained linearly off the incremental change-feed head
``9e41f1184d8a`` — one head, no branch. The auth ``app_user``/``assignment`` tables already
exist (``b7e2c1a4d9f0``) and are REUSED, not recreated.

Tables:
* ``remediation_plan`` / ``remediation_plan_item`` — persisted plan header + prior-state items.
* ``action_job`` — signed single-use job ledger.
* ``used_nonce`` — UNIQUE nonce, the atomic replay-rejection ledger (T-3).
* ``remediation_audit`` — hash-chained append-only audit (UNIQUE row_hash, indexed prev_hash).
* ``remediation_audit_checkpoint`` — periodic signed head anchor (truncation detection).

All types are portable (String / Integer / BigInteger / JSON / DateTime(timezone=True)) so the
SQLite test suite stays green alongside PostgreSQL; no Postgres-only DDL is required for these
tables (unlike fs_entry partitioning).

Append-only discipline: in production the API DB role is granted SELECT/INSERT but NOT
UPDATE/DELETE on ``remediation_audit`` (and the audit checkpoint), so a compromised API cannot
rewrite or truncate the chain; admin/auditor get read-only. Those GRANTs are managed at the
role layer (out of Alembic's portable DDL scope) and documented in the enablement runbook.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c3f1a9b8e210"
down_revision: str | None = "9e41f1184d8a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remediation_plan",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("plan_id", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("host_id", sa.String(length=255), nullable=False),
        sa.Column("keeper_path", sa.String(length=4096), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="built"),
        sa.Column("blast_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reclaimable_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("plan_id", name="uq_remediation_plan_plan_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_remediation_plan_idempotency"),
    )

    op.create_table(
        "remediation_plan_item",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("plan_id", sa.Integer(), nullable=False),
        sa.Column("entry_id", sa.BigInteger(), nullable=False),
        sa.Column("path", sa.String(length=4096), nullable=False),
        sa.Column("prior_inode", sa.BigInteger(), nullable=False),
        sa.Column("prior_size", sa.BigInteger(), nullable=False),
        sa.Column("prior_hash", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(["plan_id"], ["remediation_plan.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_remediation_plan_item_plan_id"),
        "remediation_plan_item",
        ["plan_id"],
        unique=False,
    )

    op.create_table(
        "action_job",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("plan_id", sa.Integer(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.String(length=512), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("dispatched_to_host", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="issued"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["plan_id"], ["remediation_plan.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", name="uq_action_job_job_id"),
    )
    op.create_index(op.f("ix_action_job_plan_id"), "action_job", ["plan_id"], unique=False)

    op.create_table(
        "used_nonce",
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column(
            "consumed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # PK on nonce is the UNIQUE constraint that makes consume atomic (insert-or-fail, T-3).
        sa.PrimaryKeyConstraint("nonce"),
    )

    op.create_table(
        "remediation_audit",
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("ts", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=4096), nullable=False),
        sa.Column("before_state", sa.JSON(), nullable=False),
        sa.Column("result", sa.String(length=64), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("row_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("seq"),
        sa.UniqueConstraint("row_hash", name="uq_remediation_audit_row_hash"),
    )
    op.create_index(
        "ix_remediation_audit_prev_hash",
        "remediation_audit",
        ["prev_hash"],
        unique=False,
    )

    op.create_table(
        "remediation_audit_checkpoint",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("row_hash", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=512), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    # Reverse FK order (children before parents).
    op.drop_table("remediation_audit_checkpoint")
    op.drop_index("ix_remediation_audit_prev_hash", table_name="remediation_audit")
    op.drop_table("remediation_audit")
    op.drop_table("used_nonce")
    op.drop_index(op.f("ix_action_job_plan_id"), table_name="action_job")
    op.drop_table("action_job")
    op.drop_index(op.f("ix_remediation_plan_item_plan_id"), table_name="remediation_plan_item")
    op.drop_table("remediation_plan_item")
    op.drop_table("remediation_plan")
