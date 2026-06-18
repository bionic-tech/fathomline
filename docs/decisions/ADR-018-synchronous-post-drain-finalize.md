# ADR-018: Synchronous post-drain finalize for rollups + report-only dedup

**Status:** Accepted **Date:** 2026-06-06 **Deciders:** project owner

## Context

The agent-push transport (ADR-002) lands raw `fs_entry` deltas through
`POST /api/v1/agents/ingest` (`src/fathom/api/routers/ingest.py`). Ingest is the
*only* thing the drain calls, and ingest writes entry rows and nothing else. Two
read surfaces depend on aggregates that the ingest path never computes:

- **Subtree totals.** The UI tree/treemap read `subtree_rollup` for instant
  drill-down sizes (ADD 09 §8). Without a bottom-up pass over the freshly-landed
  entries there is no rollup, so the tree shows no sizes and the Scans view's
  `Entries` / `On-disk` / `Finished` columns (ADD 09 §4) stay `0`/`null` — the
  snapshot is opened at scan start but cannot know its final entry count or
  on-disk size until the rollup exists.
- **Report-only dup groups.** A full-bit pass stages `full_hash` values that ride
  the same drain as the metadata deltas, but nothing groups equal hashes into
  `dup_group` / `dup_member` rows. Without a trigger the `/duplicates` view stays
  empty even after content has been hashed. The grouping logic exists —
  `DedupService` (`src/fathom/core/dedup_service.py`, ADR-011) builds those tables
  purely from the stored `full_hash`, never opening a file — but nothing invokes
  it.

ADD 02 §7.1 names an **arq `dedup` queue on Valkey** ("Build groups from
hashes; rank keepers — after full-bit ingest") as the intended home for the
grouping work, alongside a `scan` queue. That broker is not yet provisioned, and
§7.1 says nothing about how the grouping runs before it is. Running
`DedupService` **synchronously post-drain** until the queue exists is *this*
ADR's decision, and the choice already recorded in ADD 09 (the
`09-data-storage-access.md` finalize section calls the inline rebuild the
"documented interim"). We need the rollups and dup groups to exist *now*, without
standing up Valkey + arq first, and without trusting the agent to compute them
(the agent reads its own host; the server owns the catalogue and its aggregates —
AR-0012).

## Decision

After its drain completes, the agent makes a single additional call:
`POST /api/v1/agents/finalize` (`src/fathom/agent/runner.py::_mtls_finalize`,
`FINALIZE_PATH = "/api/v1/agents/finalize"`), over the **same CA-pinned mTLS
channel as ingest**. The endpoint (`finalize_rollups` in
`src/fathom/api/routers/ingest.py`) carries the identical trust boundary to
`/ingest`: the same `FingerprintDep` (mTLS + ingest-proxy secret), off the
human-auth path. The calling host is its **cert fingerprint, never the request
body** — finalize takes no body — and the server only ever touches **that host's**
volumes (AR-0012).

Server-side, `FinalizeService.finalize_host(cert_fingerprint=...)`
(`src/fathom/core/finalize.py`) does three things, all inside the caller's single
transaction:

1. **Recompute rollups for the host's stale volumes.** A volume is *stale* iff
   its latest `snapshot.started` is at/after its most recent
   `subtree_rollup.computed_at`, or it has snapshots but no rollup yet
   (`_stale_volume_ids` — two aggregate sub-selects keyed by `volume_id`).
   "Touched since last finalize" is thus derived from the append-only catalogue
   itself; no extra bookkeeping column is added. For each stale volume,
   `RollupService.recompute_full` (`src/fathom/core/rollup.py`) streams the live
   (`present`) entry rows and rebuilds `subtree_rollup` bottom-up, replacing the
   volume's prior rollup atomically and appending one `size_history` point.
2. **Stamp the scan snapshot totals.** `_finalize_snapshot_stats` copies the root
   (mountpoint) rollup's `total_size_on_disk` and `file_count` onto every
   *unfinished* snapshot of that volume and marks them `finished` — populating the
   Scans view columns. Only unfinished snapshots are touched, so a re-finalize
   never rewrites a closed scan's record.
3. **Rebuild estate-wide report-only dup groups when full hashes exist.**
   `_rebuild_dedup` first checks whether any `fs_entry.full_hash` is non-null
   (a single `LIMIT 1` probe); if none, it returns `0` and does nothing — a
   metadata-only deployment never pays for a dedup scan. When hashes are present
   it calls `DedupService.build(scope=DedupScope(), job_id="finalize")`. The
   scope is **estate-wide** (empty `DedupScope`), so a duplicate spanning two
   volumes or two hosts surfaces, not just within the finalizing host. The build
   flushes into the **same transaction** as the rollups — both `recompute_full`
   and `DedupService.build` flush, and the request-scoped `db_session` dependency
   (`src/fathom/api/deps.py`, commit-on-success) owns the single commit. Inline
   dedup is the default
   (`build_dedup=True`) and can be disabled per-deployment once the arq `dedup`
   queue drives the grouping, without losing the rollup finalize.

The call is **idempotent and cheap to repeat**: a host with nothing new since its
previous finalize selects no stale volumes and recomputes nothing (empty
`FinalizeResult`); `recompute_full` deletes-and-replaces the volume's rollup; and
`DedupService.build(replace=True)` clears and rebuilds the estate-wide scope each
time. In the normal flow the agent finalizes once per run, right after the drain.

Finalize is **best-effort on the agent side**: the deltas are already ingested, so
a finalize failure is logged and swallowed (`run_agent` catches it and sets
`finalized=None`) — only the rollups lag until the next run; it never aborts an
otherwise-good scan.

### Alternatives considered

- **Stand up the arq `dedup` broker now (ADD 02 §7.1).** *Deferred.* The `dedup`
  queue named in §7.1 is the intended end state but requires provisioning Valkey +
  an arq worker deployment. Running `DedupService` synchronously until then is the
  interim chosen here (and in ADD 09's finalize section), not something §7.1
  mandates; `FinalizeService(build_dedup=...)` is the seam that lets a
  broker-driven deployment turn the inline rebuild off later without code churn.
- **Have the agent compute rollups/dup groups and push them.** *Rejected.* It
  would make the server trust agent-supplied aggregates, breaking the AR-0012
  boundary (the agent already trusts its own scope; the server must re-derive
  everything from the catalogue it owns). The agent reads only its own host;
  estate-wide dedup is inherently a server-side cross-host join.

## Consequences

### Positive
- The UI tree/treemap and Scans view show real sizes immediately after a run, and
  `/duplicates` reflects freshly-hashed content — with **no new infrastructure**.
- Rollups and dup groups commit **atomically with each other** inside one
  transaction, so a reader never sees rollups without the matching groups (or
  vice versa).
- Idempotent by construction: re-running finalize, or running it after a partial
  failure, converges to the same state and is a near-no-op when nothing changed.
- Preserves the ingest trust boundary exactly (AR-0012, ADR-002): same mTLS +
  proxy-secret `FingerprintDep`, host identity from the cert, scope limited to the
  caller's own volumes; dedup stays strictly report-only (`dedup_service.py`,
  "security_constraints: report-only boundary") — groups only on a full BLAKE3
  match (ADD 09 §5), opens no file, writes only the report tables, drives no
  remediation.
- Metadata-only deployments are unaffected: zero `full_hash` rows means zero dup
  groups and no dedup scan cost.

### Negative
- The rollup recompute runs **synchronously inside the API worker**, not on a
  background queue, so a finalize occupies a request for the duration of the
  bottom-up pass; `RollupService` mitigates the memory cost with streamed reads
  and Core bulk-insert batches, but the *latency* of a large volume is borne in
  the request.
- `recompute_full` is a **full** rebuild of the affected volume's rollup each
  finalize; the incremental ancestor-only recompute noted in
  `src/fathom/core/rollup.py` is a later optimisation, so a small incremental scan
  still triggers a whole-volume rollup pass.
- The estate-wide dedup rebuild is **re-run on every finalize that sees any
  hashes**, regardless of which host called — work that the dedicated arq `dedup`
  queue would schedule more selectively.

### Risks
- **API-worker resource pressure under concurrent finalizes.** Multiple hosts
  finalizing large volumes at once contend for the same worker pool and DB.
  Mitigated by the streamed/bounded-memory rollup path and by finalize running
  once per run after the drain; the arq `dedup`/`scan` queues (ADD 02 §7.1) remain
  the deferred path for moving this off the request lifecycle. *Follow-up:*
  throughput under concurrent multi-host finalize is not yet load-characterised.
- **Stale-volume detection depends on snapshot/rollup timestamps.** A clock skew
  or an out-of-order `computed_at` could mis-classify a volume as fresh and skip
  its rollup. Bounded by the idempotent design — the next finalize re-evaluates
  staleness and recomputes — and by deriving staleness from the append-only
  catalogue rather than a mutable flag.
