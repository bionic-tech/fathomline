# ADR-015: Device id in the catalogue entry identity

**Status:** Accepted **Date:** 2026-06-06 **Deciders:** project owner

## Context
A catalogue entry's identity was `(host_id, volume_id, inode)` — the unique key behind both
the agent's SQLite staging upsert (`src/fathom/agent/staging/store.py`) and the central
catalogue upsert (`uq_fs_entry_identity` in `src/fathom/core/catalogue/models.py`,
`FsEntryRow`). On a single filesystem this is sound: `inode` is unique within one filesystem,
so the key is too.

The agent's `cross_mounts` mode breaks that assumption. `cross_mounts=True` turns the walk's
`one_filesystem` guard off (`one_filesystem=not config.cross_mounts`,
`src/fathom/agent/runner.py:158`), so a walk rooted at one logical volume descends past the
root filesystem into nested mounts — concretely, the ZFS child datasets under a pool root.
Each ZFS child dataset is its own filesystem with its own inode space, and each reuses low
inode numbers from the same small range. Two files in two different datasets therefore share
an `inode` and collide on the upsert key, clobbering each other. The migration records this
confirmed live: a cross-dataset scan of `tank` (38 child datasets on the TrueNAS host) kept
only the largest dataset's subtree (`migrations/versions/f6c4d8a1b2e7_fs_entry_dev_identity.py`,
header). This is the cross-dataset scan scope of the production deployment. The walk's filesystem
crossing is a `StorageBackend` concern — `PosixBackend._should_descend` gates descent on
`st_dev` (ADR-004 `StorageBackend` Protocol) — while host topology stays separate: ADR-008's
`PlatformAdapter` reads pool/resilver state from the NAS API (`pool.status`), not from the
catalogue entries.

POSIX already exposes the discriminator: `os.stat_result.st_dev` differs per filesystem.
`PosixBackend._entry` reads it as `dev=stat.st_dev`
(`src/fathom/backends/posix.py:243`), and the same `st_dev` value already gates whether the
walk descends across a mount (`_should_descend`, `src/fathom/backends/posix.py:277`). It was
captured on the in-memory `FsEntry.dev` but never threaded into the entry identity.

## Decision
Make the device id part of the entry identity. The catalogue uniqueness becomes
`(host_id, volume_id, dev, inode)`:

- `FsEntry.dev` (`src/fathom/backends/base.py:75`) carries `st_dev` from the backend; remote
  backends with no local device concept leave it `0`.
- `FsEntryRow.dev` is a `BigInteger` with `default=0, server_default="0"`, and
  `uq_fs_entry_identity` is `UniqueConstraint("host_id", "volume_id", "dev", "inode")`
  (`src/fathom/core/catalogue/models.py:108`, `:135`).
- The ingest upsert conflict target lists all four columns —
  `index_elements=[host_id, volume_id, dev, inode]` in `IngestService._upsert_entries`
  (`src/fathom/core/ingest.py:341`) — and `_vet_entries` carries `dev` onto every staged row
  (`src/fathom/core/ingest.py:117`). The agent's SQLite staging key is widened to match
  (`src/fathom/agent/staging/store.py`).
- `dev` defaults to `0`, which is **behaviour-preserving**: within a single filesystem `inode`
  is already unique, so `dev = 0` for every row changes no key. Single-filesystem scans and
  remote backends are unaffected.

### Alternatives considered
- **Keep inode-only identity** — *rejected.* It is the bug: inode collides across ZFS child
  datasets that reuse low inode numbers, and the colliding rows clobber each other on upsert.
- **One catalogue `Volume` per dataset** — *rejected.* It would give every dataset a distinct
  `volume_id` and so a distinct key, but it explodes the volume count (38 datasets under one
  pool root on the TrueNAS host alone), fragments a single logical volume's reporting, and pushes
  filesystem-internal structure into the volume model. `dev` discriminates the same datasets
  without inventing volumes.
- **Path-based identity** — *rejected.* Keying on `path` makes a rename a delete-plus-create,
  losing the entry's history (size trend, hashes, churn). Inode identity is precisely what
  lets a renamed file keep its row; the incremental present/removed lifecycle (ADR-006) and a
  re-appearing inode resurrecting to `present` both depend on a stable inode-based key.

## Consequences
### Positive
- Cross-dataset `cross_mounts` scans catalogue every dataset's tree correctly; no
  cross-dataset clobbering. The 38-child `tank` scan retains all subtrees, not just
  the largest.
- Behaviour-preserving for single-filesystem and remote scans (`dev` defaults to `0`); no
  reporting, dedup, or incremental behaviour changes outside cross-mount walks.
- The new unique still contains both partition-key columns (`host_id`, `volume_id`), which
  PostgreSQL requires for a unique on a LIST-partitioned table, so it stays a valid
  `ON CONFLICT` target (ADR-003 partitioning;
  `migrations/versions/f6c4d8a1b2e7_fs_entry_dev_identity.py` header).

### Negative
- A schema migration plus a re-scan were required to recapture `dev` for already-catalogued
  estates: rows written before the change carry `dev = 0` regardless of their true device, so
  a cross-mount re-scan recaptured the real `st_dev` on every entry. (Within a single
  filesystem `dev = 0` is correct as-is and needed nothing.)
- One more column on the hottest, largest table (`fs_entry`, 50M+ rows) and on the staging
  key.
- `dev` is threaded end-to-end only on the metadata upsert path (`PosixBackend._entry` →
  `stage_batch` carries `e.dev`, `src/fathom/agent/staging/store.py:136`), which is where the
  collisions actually clobbered data. Three other staging paths still default `dev = 0` with
  explicit module TODOs: `stage_removals` (the change feed reports `(inode, path)` only),
  `stage_hash` (the full-bit funnel), and `load_baseline` (keyed on inode). A cross-dataset
  removal, full-bit, or baseline therefore remains a follow-up (`store.py:181-183`, `:246-247`,
  `:282`).

### Risks
- **PostgreSQL partitioned-table DDL.** The unique swap is raw `ALTER` DDL on the partitioned
  parent; `ADD COLUMN` must propagate to every current and future partition. Mitigated: the
  migration adds the column and swaps the constraint explicitly, and the new unique keeps both
  partition-key columns so it remains creatable on the partitioned table
  (`f6c4d8a1b2e7_fs_entry_dev_identity.py`, `upgrade()`).
- **SQLite cannot `ALTER … ADD/DROP CONSTRAINT`.** Dev/test runs the column add and constraint
  swap inside one `batch_alter_table(recreate="always")` table-copy rebuild, which backfills
  every existing row to `dev = 0` via the `server_default` (same migration, SQLite branch).
- **A genuinely device-less backend reporting a non-zero `dev`** would split identities
  spuriously; mitigated by the `dev = 0` default and remote backends not setting it.

### Follow-up
- The migration's `down_revision` chains linearly off the then-sole head `e5b3c7f2a9d1`
  (`uv run alembic heads` reported one head before this revision); confirm no branch was
  introduced when later revisions land.
