-- Fathom agent local staging schema (SQLite, WAL mode).
-- Mirrors the catalogue's idempotent upsert key (ADD 09 §2): (host_id, volume_id, dev, inode)
-- with a change guard on (mtime, size_logical). Re-staging an unchanged entry is a no-op,
-- which is what makes a push resumable without duplicate ingest (ADD 02 §7.2). ``dev`` (st_dev)
-- is in the key because a cross_mounts walk spans ZFS child datasets that each reuse low inode
-- numbers — inode alone collides across datasets and clobbers sibling subtrees. It defaults to 0
-- so a single-filesystem scan (inode already unique) is unaffected.
--
-- This DB is disposable: it stages deltas pending push, then they are pruned. It is not a
-- system of record.

CREATE TABLE IF NOT EXISTS scan_run (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       TEXT    NOT NULL,
    volume_id     TEXT    NOT NULL,
    mode          TEXT    NOT NULL CHECK (mode IN ('metadata', 'fullbit')),
    root          TEXT    NOT NULL,
    started_at    REAL    NOT NULL,
    finished_at   REAL,
    entry_count   INTEGER NOT NULL DEFAULT 0,
    warning_ack   TEXT,                                -- JSON: operator, ts, target, mode
    volume_json   TEXT                                 -- JSON VolumeInfo, so push survives restart
);

CREATE TABLE IF NOT EXISTS staged_entry (
    host_id       TEXT    NOT NULL,
    volume_id     TEXT    NOT NULL,
    dev           INTEGER NOT NULL DEFAULT 0,         -- st_dev; part of the identity (ZFS datasets)
    inode         INTEGER NOT NULL,
    path          TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    is_dir        INTEGER NOT NULL,
    is_symlink    INTEGER NOT NULL,
    size_logical  INTEGER NOT NULL,
    size_on_disk  INTEGER NOT NULL,
    mtime         REAL    NOT NULL,
    ctime         REAL    NOT NULL,
    uid           INTEGER NOT NULL,
    gid           INTEGER NOT NULL,
    flags         TEXT    NOT NULL DEFAULT '{}',        -- JSON
    -- Content hashes carried for full-bit runs only (NULL for metadata). Staged under the
    -- same (host_id, volume_id, dev, inode) PK so a full-bit run resumes without re-hashing
    -- already-staged files (fullbit-dedup data_model_changes).
    partial_hash  TEXT,
    full_hash     TEXT,
    scan_run_id   INTEGER NOT NULL REFERENCES scan_run(id),
    pushed        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, volume_id, dev, inode)
);

-- Drains the push queue in insertion order without scanning pushed rows.
CREATE INDEX IF NOT EXISTS idx_staged_unpushed
    ON staged_entry (pushed, scan_run_id);

-- A full-bit run resumes from the first not-yet-hashed file in scope: this finds rows that
-- have been staged (metadata) but not yet content-hashed, cheaply.
CREATE INDEX IF NOT EXISTS idx_staged_unhashed
    ON staged_entry (full_hash, scan_run_id);

-- The full-bit funnel groups candidates by size within a scope (a unique size is never opened).
-- This index makes "sizes shared by >=2 files" and "all files of a given size" cheap, so full-bit
-- streams one size-group at a time (bounded memory) instead of materialising every candidate —
-- which OOM-killed the scanner on million-file hosts (ADR-025 scan-fix).
CREATE INDEX IF NOT EXISTS idx_staged_fullbit_size
    ON staged_entry (host_id, volume_id, is_dir, is_symlink, size_logical);

-- Explicit deletions detected by the incremental change feed (ADR-006, incremental subsystem).
-- A removal is staged here (NOT inferred from a missing staged_entry) and pushed alongside the
-- run's upserts so the server can flip the catalogue row to present=false. Keyed by the same
-- (host_id, volume_id, dev, inode) business key as staged_entry; resumable/idempotent like the rest.
CREATE TABLE IF NOT EXISTS staged_removal (
    host_id       TEXT    NOT NULL,
    volume_id     TEXT    NOT NULL,
    dev           INTEGER NOT NULL DEFAULT 0,         -- st_dev; matches staged_entry's identity
    inode         INTEGER NOT NULL,
    path          TEXT    NOT NULL,
    scan_run_id   INTEGER NOT NULL REFERENCES scan_run(id),
    pushed        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, volume_id, dev, inode)
);

CREATE INDEX IF NOT EXISTS idx_removal_unpushed
    ON staged_removal (pushed, scan_run_id);
