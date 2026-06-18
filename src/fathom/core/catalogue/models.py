"""SQLAlchemy 2.0 typed models for the catalogue (ADD 09 §2).

Append-only by discipline: ``snapshot`` and ``size_history`` are never updated in place;
``fs_entry`` is upserted idempotently on ``(host_id, volume_id, dev, inode)`` with a change
guard on ``(mtime, size_logical)`` so a resumed push never duplicates rows (ADD 02 §7.2).
``dev`` (st_dev) is in the identity because a cross_mounts walk spans ZFS child datasets that
reuse low inode numbers — inode alone collides across datasets; it defaults to 0.
Types are kept portable (BigInteger / JSON / Float-epoch) so the same models run on
PostgreSQL and on SQLite under test.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all catalogue tables."""


class Host(Base):
    """An agent-bearing host, keyed in practice by its mTLS cert fingerprint."""

    __tablename__ = "host"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    os: Mapped[str | None] = mapped_column(String(255), default=None)
    agent_version: Mapped[str | None] = mapped_column(String(64), default=None)
    cert_fingerprint: Mapped[str] = mapped_column(String(128), unique=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    # ADR-033 agent config. reported_config = the EFFECTIVE config the agent last ran with (shown in
    # the UI, #9); desired_config = the operator's per-host OVERRIDE the agent pulls + re-validates
    # at run start and applies fail-safe (#10). Both nullable: null reported = pre-ADR-033 agent;
    # null desired = no override (agent runs its local file unchanged).
    reported_config: Mapped[dict[str, object] | None] = mapped_column(JSON, default=None)
    desired_config: Mapped[dict[str, object] | None] = mapped_column(JSON, default=None)

    volumes: Mapped[list[Volume]] = relationship(back_populates="host")


class Volume(Base):
    """A mounted volume with capacity and storage topology (ADD 04)."""

    __tablename__ = "volume"
    __table_args__ = (UniqueConstraint("host_id", "mountpoint", name="uq_volume_host_mount"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id"))
    mountpoint: Mapped[str] = mapped_column(String(4096))
    # Human label when ``mountpoint`` is a synthetic path (remote/cloud volumes — ADR-029): the UI
    # shows this (e.g. ``rclone://gdrive/Backups``) instead of the synthetic ``/rclone/...`` mount.
    # NULL for local volumes, where the mountpoint is already the natural display.
    display_name: Mapped[str | None] = mapped_column(String(4096), default=None)
    # Root/system vs data volume: 'system' volumes are metadata-only at the human-RBAC layer
    # and scope/capability-gated so 'root-volume view' never equals root (AR-011, ADD 13 §4).
    kind: Mapped[str] = mapped_column(String(16), default="data", server_default="data")
    fs_type: Mapped[str] = mapped_column(String(64))
    device: Mapped[str] = mapped_column(String(255))
    transport: Mapped[str] = mapped_column(String(32))
    raid_role: Mapped[str | None] = mapped_column(String(255), default=None)
    pool: Mapped[str | None] = mapped_column(String(255), default=None)
    dataset: Mapped[str | None] = mapped_column(String(255), default=None)
    total: Mapped[int] = mapped_column(BigInteger, default=0)
    used: Mapped[int] = mapped_column(BigInteger, default=0)
    free: Mapped[int] = mapped_column(BigInteger, default=0)
    # Per-volume churn feed toggle (ADD 09 §2: "ENABLED per-volume"). Default ON; an operator
    # can turn it off for a volume whose change history is not worth the write/retention cost
    # (incremental owner ruling: change_log default ON per volume). When False the ingest
    # reconciliation still maintains present/removed_at but writes no change_log rows.
    change_log_enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    host: Mapped[Host] = relationship(back_populates="volumes")


class Snapshot(Base):
    """An immutable scan run; the unit of time-series history (append-only)."""

    __tablename__ = "snapshot"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id"))
    volume_id: Mapped[int] = mapped_column(ForeignKey("volume.id"))
    mode: Mapped[str] = mapped_column(String(16))  # metadata | fullbit
    started: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    total_size: Mapped[int] = mapped_column(BigInteger, default=0)
    file_count: Mapped[int] = mapped_column(BigInteger, default=0)
    warning_ack: Mapped[dict[str, object] | None] = mapped_column(JSON, default=None)


class AgentRun(Base):
    """One agent run outcome, reported by the agent at end-of-run (observability).

    Fleet observability: an operator needs to see, per host, whether the *last scan actually
    succeeded* — not just that the agent last made contact. The agent computes a per-scope
    summary (entries, changes, errors, full-bit status) and reports it over the same mTLS boundary
    as ingest; the server re-derives the aggregate outcome (never trusting an agent-asserted
    aggregate — AR-0012) and appends a row here. ``outcome`` is ``ok`` (no scope errored),
    ``partial`` (some scopes errored), or ``failed`` (all scopes errored / nothing scanned).
    """

    __tablename__ = "agent_run"
    __table_args__ = (Index("ix_agent_run_host_created", "host_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[str] = mapped_column(String(16))  # ok | partial | failed
    entries_seen: Mapped[int] = mapped_column(BigInteger, default=0)
    rows_changed: Mapped[int] = mapped_column(BigInteger, default=0)
    pushed: Mapped[int] = mapped_column(BigInteger, default=0)
    scopes_total: Mapped[int] = mapped_column(Integer, default=0)
    scopes_failed: Mapped[int] = mapped_column(Integer, default=0)
    finalized: Mapped[int | None] = mapped_column(Integer, default=None)
    # First per-scope error message (truncated) so a failure is diagnosable from the run row.
    error_summary: Mapped[str | None] = mapped_column(String(1024), default=None)
    agent_version: Mapped[str | None] = mapped_column(String(64), default=None)
    # ADR-033: the effective config this run used (per-run audit trail of config drift).
    reported_config: Mapped[dict[str, object] | None] = mapped_column(JSON, default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class FsEntryRow(Base):
    """One catalogued filesystem entry (ADD 09 §2).

    In production this table is LIST-partitioned by ``host_id`` (sub-partition by
    ``volume_id``) via an Alembic migration; the ORM stays partition-agnostic. ``path`` is
    a materialised path indexed with ``text_pattern_ops`` for prefix subtree queries.
    """

    __tablename__ = "fs_entry"
    __table_args__ = (
        UniqueConstraint("host_id", "volume_id", "dev", "inode", name="uq_fs_entry_identity"),
        # Backs the dedup grouping scan: group stored full hashes within a volume scope
        # (fullbit-dedup spec, ADD 09 §2). Migration adds it as partial WHERE full_hash IS
        # NOT NULL on PostgreSQL so it stays tiny (only full-bit-hashed rows).
        Index("ix_fs_entry_volume_full_hash", "volume_id", "full_hash"),
        # Backs the report-only provider-hash duplicate grouping (ADR-028 phase 2). Migration
        # makes it partial WHERE provider_hash IS NOT NULL on PostgreSQL so it stays tiny.
        Index("ix_fs_entry_provider_hash", "provider_hash_algo", "provider_hash"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id"), index=True)
    volume_id: Mapped[int] = mapped_column(ForeignKey("volume.id"), index=True)
    parent_id: Mapped[int | None] = mapped_column(default=None)
    name: Mapped[str] = mapped_column(String(1024))
    path: Mapped[str] = mapped_column(String(4096), index=True)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    is_dir: Mapped[bool] = mapped_column(Boolean, default=False)
    is_symlink: Mapped[bool] = mapped_column(Boolean, default=False)
    size_logical: Mapped[int] = mapped_column(BigInteger, default=0)
    size_on_disk: Mapped[int] = mapped_column(BigInteger, default=0)
    mtime: Mapped[float] = mapped_column(Float, default=0.0)
    ctime: Mapped[float] = mapped_column(Float, default=0.0)
    uid: Mapped[int] = mapped_column(Integer, default=0)
    gid: Mapped[int] = mapped_column(Integer, default=0)
    inode: Mapped[int] = mapped_column(BigInteger)
    # Device id (``st_dev``) — part of the entry identity. A cross_mounts walk spans ZFS child
    # datasets that each have their own inode space and reuse low inode numbers, so inode alone
    # collides across datasets; the uniqueness is (host_id, volume_id, dev, inode). Defaults to 0
    # (single-filesystem scans, where inode is already unique, and remote backends).
    dev: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    flags: Mapped[dict[str, bool]] = mapped_column(JSON, default=dict)
    last_seen_snapshot_id: Mapped[int | None] = mapped_column(default=None)
    # Explicit presence markers for incremental deletions (incremental owner ruling: an
    # explicit present/removed_at marker, NOT snapshot-staleness inference). A live entry is
    # ``present=True, removed_at=NULL``; when the change feed reports a path gone, ingest flips
    # it to ``present=False, removed_at=<ts>`` rather than deleting the row — so deletions are a
    # first-class, queryable, reversible (a re-appearing inode resurrects to present) fact, and
    # a subtree's history survives the file that produced it (ADD 09 §2, ADR-006). Reads default
    # to ``present=True`` so a deleted entry never inflates a current-state tree/size.
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1", index=True)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    # Content hashes — set ONLY by a full-bit ingest; a metadata scan leaves them NULL
    # (NULL = never full-bit-hashed). BLAKE3 hexdigest is 64 hex chars (fullbit-dedup spec,
    # ADD 09 §5: grouping requires a full BLAKE3 match). The hashes live on the partitioned
    # parent (design_questions: column-vs-table — chosen per file-mgmt §1.3 "catalogue stores
    # metadata, hashes"); the (volume_id, full_hash) index backs the dedup grouping scan.
    partial_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    full_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    hashed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    # Provider-attested content hash + its algorithm (ADR-028 phase 2). A DISTINCT trust class
    # from full_hash: set on a *metadata* batch from a backend that obtained a hash the provider
    # already computed (rclone `lsjson --hash`) without the agent reading bytes. NEVER conflated
    # with full_hash and NEVER drives remediation (which keys on the BLAKE3 full_hash) — it backs
    # only the report-only provider-hash duplicate grouping. The (algo, hash) index makes that
    # grouping scan cheap (migration makes it partial WHERE provider_hash IS NOT NULL on PG).
    provider_hash: Mapped[str | None] = mapped_column(String(128), default=None)
    provider_hash_algo: Mapped[str | None] = mapped_column(String(32), default=None)


class SubtreeRollup(Base):
    """Maintained subtree totals for instant drill-down sizes (ADD 09 §8)."""

    __tablename__ = "subtree_rollup"
    __table_args__ = (UniqueConstraint("volume_id", "path", name="uq_rollup_vol_path"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    volume_id: Mapped[int] = mapped_column(ForeignKey("volume.id"), index=True)
    path: Mapped[str] = mapped_column(String(4096))
    depth: Mapped[int] = mapped_column(Integer, default=0)
    total_size_logical: Mapped[int] = mapped_column(BigInteger, default=0)
    total_size_on_disk: Mapped[int] = mapped_column(BigInteger, default=0)
    file_count: Mapped[int] = mapped_column(BigInteger, default=0)
    dir_count: Mapped[int] = mapped_column(BigInteger, default=0)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class SizeHistory(Base):
    """Cheap aggregate history rows for growth-over-time (append-only, ADD 09 §2)."""

    __tablename__ = "size_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    volume_id: Mapped[int] = mapped_column(ForeignKey("volume.id"), index=True)
    path: Mapped[str] = mapped_column(String(4096))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    total_size_logical: Mapped[int] = mapped_column(BigInteger, default=0)
    total_size_on_disk: Mapped[int] = mapped_column(BigInteger, default=0)
    file_count: Mapped[int] = mapped_column(BigInteger, default=0)


class ChangeLog(Base):
    """Per-path churn rows — the "what changed" feed (ADD 09 §2/§4, ADR-006).

    A byproduct of the incremental change feed: each reconciliation of an agent delta against
    the catalogue emits one row per created / modified / removed path. ``change_type`` is one of
    :data:`CHANGE_TYPES`; ``size_delta`` is ``new_size_logical - old_size_logical`` (signed:
    negative on shrink/removal, the full size on create, zero on a pure metadata touch). The feed
    is **enabled per volume** (``Volume.change_log_enabled``, default ON) and **retention-capped**
    at :data:`CHANGE_LOG_RETENTION_DAYS` days by the pruner (incremental owner ruling: change_log
    default ON per volume, 90-day retention). Append-only; never updated in place.
    """

    __tablename__ = "change_log"
    __table_args__ = (
        # Backs the churn read (a path/window scan) and the retention prune (a ts scan).
        Index("ix_change_log_volume_ts", "volume_id", "ts"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    volume_id: Mapped[int] = mapped_column(ForeignKey("volume.id"), index=True)
    path: Mapped[str] = mapped_column(String(4096))
    # One of CHANGE_TYPES. A plain string (not an enum column) keeps the DDL portable across
    # PostgreSQL and SQLite (models module docstring: portable types).
    change_type: Mapped[str] = mapped_column(String(8))
    size_delta: Mapped[int] = mapped_column(BigInteger, default=0)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class DupGroup(Base):
    """A confirmed full-bit duplicate group — report only (ADD 09 §2, ADR-011).

    Built by :class:`fathom.core.dedup_service.DedupService` purely from stored ``fs_entry``
    full hashes (full-BLAKE3-confirmed; never size/partial-only). ``reclaimable_bytes`` is
    ``size * (member_count - 1)`` — the bytes freed if all-but-one copy were removed — and
    ``suggested_keeper_entry_id`` is a **non-binding** suggestion (oldest → preferred
    volume/path → shortest path); the report commits no filesystem change.
    """

    __tablename__ = "dup_group"

    id: Mapped[int] = mapped_column(primary_key=True)
    full_hash: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    member_count: Mapped[int] = mapped_column(Integer)
    reclaimable_bytes: Mapped[int] = mapped_column(BigInteger)
    # The dedup job scope that produced this group. JSONB on PostgreSQL so the estate-wide rebuild
    # can look up a group BY scope (``WHERE scope = :scope``) — the ``json`` type has no equality
    # operator on PG, which silently passed on SQLite but threw ``operator does not exist: json =
    # json`` in production, leaving the Duplicates view empty despite hashed content. SQLite keeps
    # the portable ``JSON`` (text) form, which compares fine.
    scope: Mapped[dict[str, object] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), default=None
    )
    job_id: Mapped[str | None] = mapped_column(String(64), default=None)
    # A non-binding suggested keeper (ADR-011); references fs_entry by its surrogate id. No
    # composite DB FK into the LIST-partitioned fs_entry (design_questions) — app-enforced.
    suggested_keeper_entry_id: Mapped[int | None] = mapped_column(BigInteger, default=None)
    suggested_keeper_reason: Mapped[str | None] = mapped_column(String(255), default=None)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    members: Mapped[list[DupMember]] = relationship(
        back_populates="group", cascade="all, delete-orphan"
    )


class DupMember(Base):
    """One member of a :class:`DupGroup` (ADD 09 §2).

    References its catalogue entry by both the surrogate ``entry_id`` and the
    ``(host_id, volume_id)`` business-key columns: there is **no** composite DB FK into the
    partitioned ``fs_entry`` parent (a single-column FK on ``entry_id`` is not creatable on a
    table whose PK is ``(id, host_id, volume_id)``), so referential integrity is app-enforced
    (DEFAULTS, design_questions). ``host_id``/``volume_id`` make scope-filtering a member-level
    predicate so the read API never leaks an out-of-scope path (security_constraints).
    """

    __tablename__ = "dup_member"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("dup_group.id"), index=True)
    entry_id: Mapped[int] = mapped_column(BigInteger)
    host_id: Mapped[int] = mapped_column(Integer)
    volume_id: Mapped[int] = mapped_column(Integer)
    path: Mapped[str] = mapped_column(String(4096))
    # True when this member lives on a NETWORK-mounted volume (NFS/SMB/sshfs/…): it is not a
    # separate physical copy but a remote *view* of a file whose bytes live on another host, so it
    # is a cross-mount ALIAS, not reclaimable space. Surfaced in the UI as a false-positive
    # duplicate and excluded from the group's ``reclaimable_bytes`` (cross-mount dedup, ADR-032).
    is_mount_alias: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")

    group: Mapped[DupGroup] = relationship(back_populates="members")
