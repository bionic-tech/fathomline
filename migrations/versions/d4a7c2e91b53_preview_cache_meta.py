"""preview cache meta

Revision ID: d4a7c2e91b53
Revises: c3f1a9b8e210
Create Date: 2026-06-06 09:00:00.000000

Preview-worker schema (preview-worker spec; ADD 02 §3). Chained linearly off the current head
``c3f1a9b8e210`` (remediation_write_path) — one head, no branch.

Adds the ``preview_cache_meta`` table: **metadata only** for the encrypted derived-artifact
cache (ADR-014; STRIDE I-8). It holds NO raw bytes and no artifact bytes — only the content
hash, detected type, the size of the *encrypted* artifact at rest, created/expiry timestamps
(created_at + 30-min TTL), and cache hit/miss accounting. Portable types (BigInteger / String /
DateTime(timezone=True)) so it runs on PG16 and on SQLite under test; no partitioning needed
(bounded LRU, small).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4a7c2e91b53"
down_revision: str | None = "c3f1a9b8e210"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "preview_cache_meta",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("entry_id", sa.BigInteger(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("cache_key", sa.String(length=160), nullable=False),
        sa.Column("artifact_ref", sa.String(length=160), nullable=False),
        sa.Column("type", sa.String(length=16), nullable=False),
        # Size of the ENCRYPTED artifact at rest — never the raw content size (I-8).
        sa.Column("artifact_size", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_preview_cache_meta_entry_id"),
        "preview_cache_meta",
        ["entry_id"],
        unique=False,
    )
    # Backs the expiry sweep (an expires_at scan).
    op.create_index(
        "ix_preview_cache_meta_expires_at",
        "preview_cache_meta",
        ["expires_at"],
        unique=False,
    )
    # One row per content-hash + render-params key (lookup + upsert by cache_key).
    op.create_index(
        "ix_preview_cache_meta_cache_key",
        "preview_cache_meta",
        ["cache_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_preview_cache_meta_cache_key", table_name="preview_cache_meta")
    op.drop_index("ix_preview_cache_meta_expires_at", table_name="preview_cache_meta")
    op.drop_index(op.f("ix_preview_cache_meta_entry_id"), table_name="preview_cache_meta")
    op.drop_table("preview_cache_meta")
