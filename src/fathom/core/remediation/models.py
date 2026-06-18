"""SQLAlchemy 2.0 models for the remediation write path (ADR-011; DEFAULTS, data_model_changes).

These reuse the catalogue ``Base`` so a single metadata / single Alembic chain governs the
whole schema. Types are portable (String / Integer / BigInteger / JSON / DateTime) so the
SQLite test suite stays green alongside PostgreSQL.

Security shape (DEFAULTS):

* ``remediation_plan`` / ``remediation_plan_item`` — the persisted operator-approved plan
  header + the prior-state-bound items the actor re-verifies against.
* ``action_job`` — the signed single-use job ledger (one row per DRY_RUN / EXECUTE dispatch).
* ``used_nonce`` — UNIQUE ``nonce``; the atomic replay-rejection ledger (T-3).
* ``remediation_audit`` — the **persisted** hash-chained, append-only audit (ADD 03 §8): a
  UNIQUE ``row_hash`` **and a UNIQUE ``prev_hash``** make the chain verifiable, tamper-evident,
  and fork-proof across process restarts. The UNIQUE ``prev_hash`` is the concurrency arbiter:
  two appends that race off the same head produce two rows with the same ``prev_hash``; the DB
  admits exactly one (the loser hits the constraint and must retry against the new head), so the
  chain can never fork into two siblings. The chain head is resumed from the last row.
* ``remediation_audit_checkpoint`` — periodic signed head anchor (security-arch OQ3) to detect
  truncation; written opportunistically, never required for an action.

Append-only discipline: the API DB role is granted no UPDATE/DELETE on the audit tables (the
migration documents this; enforced at the grant layer in production). No ORM code updates an
audit row in place.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fathom.core.catalogue.models import Base


class RemediationPlanRow(Base):
    """A persisted operator-approved plan header (ADR-011; data_model_changes)."""

    __tablename__ = "remediation_plan"

    id: Mapped[int] = mapped_column(primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[str] = mapped_column(String(255))
    host_id: Mapped[str] = mapped_column(String(255))  # business host id the job targets
    # The single volume an Organize MOVE plan is confined to (ADR-023, adversarial-review fix). The
    # dry-run/execute routes re-assert *volume* scope against this, not just host, so a build that
    # was authorised by a volume-scoped grant is re-checked at the same granularity at act time
    # (and a volume-scoped remediator is not locked out). NULL for dedup plans (which may span
    # volumes of one host — those re-assert host scope, as before).
    volume_id: Mapped[int | None] = mapped_column(Integer, default=None)
    keeper_path: Mapped[str] = mapped_column(String(4096))
    status: Mapped[str] = mapped_column(String(16), default="built")  # built|dry_run|executed
    blast_count: Mapped[int] = mapped_column(Integer, default=0)
    reclaimable_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    # The idempotency key the building request carried (API §Idempotency); UNIQUE so a replayed
    # request returns the original plan rather than building a second one.
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True, default=None)
    # The operator-approved root a MOVE (Organize-apply) plan may relocate within (ADR-023). The
    # actor opens this as the trusted anchor and refuses any destination not reached from it via
    # non-symlink components. NULL for dedup plans (quarantine/hardlink/delete), which never move.
    move_root: Mapped[str | None] = mapped_column(String(4096), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    items: Mapped[list[RemediationPlanItemRow]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )


class RemediationPlanItemRow(Base):
    """A persisted plan item with the prior state to re-verify against (T-2/T-3)."""

    __tablename__ = "remediation_plan_item"

    id: Mapped[int] = mapped_column(primary_key=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("remediation_plan.id"), index=True)
    # References the catalogue entry by its surrogate id — no composite DB FK into the
    # LIST-partitioned fs_entry parent (DEFAULTS; app-enforced like dup_member).
    entry_id: Mapped[int] = mapped_column(BigInteger)
    path: Mapped[str] = mapped_column(String(4096))
    prior_inode: Mapped[int] = mapped_column(BigInteger)
    prior_size: Mapped[int] = mapped_column(BigInteger)
    prior_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    action: Mapped[str] = mapped_column(String(16))  # quarantine|hardlink|hard_delete|move
    # Destination for a MOVE, RELATIVE to the plan's ``move_root`` (ADR-023). Server-clamped to the
    # root at build time; the actor re-walks it component-wise under O_NOFOLLOW so a planted symlink
    # cannot redirect the move out of the approved root. NULL for every non-MOVE action.
    dest_rel: Mapped[str | None] = mapped_column(String(4096), default=None)

    plan: Mapped[RemediationPlanRow] = relationship(back_populates="items")


class ActionJobRow(Base):
    """The signed single-use job ledger (ADR-011 §Guards; data_model_changes)."""

    __tablename__ = "action_job"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[str] = mapped_column(String(64), unique=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("remediation_plan.id"), index=True)
    mode: Mapped[str] = mapped_column(String(16))  # dry_run|execute
    nonce: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    signature: Mapped[str] = mapped_column(String(512))
    key_id: Mapped[str] = mapped_column(String(128))
    algorithm: Mapped[str] = mapped_column(String(32))
    dispatched_to_host: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="issued")  # issued|completed|failed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class UsedNonceRow(Base):
    """Single-use enforcement: a replayed nonce hits the UNIQUE constraint (T-3)."""

    __tablename__ = "used_nonce"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    job_id: Mapped[str] = mapped_column(String(64))
    consumed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RemediationAuditRow(Base):
    """A persisted hash-chained, append-only audit record (ADD 03 §8; data_model_changes).

    Both ``row_hash`` and ``prev_hash`` are UNIQUE so the chain is verifiable, resumable across
    restarts, and **fork-proof**: only one row may ever point at a given predecessor, so two
    concurrent appends off the same head cannot both commit (the loser hits the UNIQUE
    ``prev_hash`` constraint and retries against the new head). No code path updates a row in
    place; the production grant denies the API role UPDATE/DELETE.
    """

    __tablename__ = "remediation_audit"
    __table_args__ = (
        UniqueConstraint("row_hash", name="uq_remediation_audit_row_hash"),
        # UNIQUE (not just indexed) prev_hash: the chain-fork arbiter under concurrent appends.
        UniqueConstraint("prev_hash", name="uq_remediation_audit_prev_hash"),
    )

    seq: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[str] = mapped_column(String(64))  # ISO-8601 as recorded into the canonical payload
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(4096))
    before_state: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    result: Mapped[str] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))


class RemediationAuditCheckpointRow(Base):
    """A periodic signed head anchor (security-architecture OQ3) — truncation detection.

    Records ``(seq, row_hash, signature)`` for the audit head at checkpoint time. A verifier can
    confirm the live chain still extends a previously-anchored head, so silently dropping the
    tail of the audit log is detectable. Optional: never on the action's critical path.
    """

    __tablename__ = "remediation_audit_checkpoint"

    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger)
    row_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(512))
    key_id: Mapped[str] = mapped_column(String(128))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
