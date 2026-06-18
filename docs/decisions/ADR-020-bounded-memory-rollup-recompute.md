# ADR-020: Bounded-memory rollup recompute (streaming read + Core bulk insert)

**Status:** Accepted **Date:** 2026-06-06 **Deciders:** project owner

## Context

`RollupService.recompute_full` (`src/fathom/core/rollup.py`) rebuilds a volume's
`subtree_rollup` baseline — the bottom-up totals the UI tree/treemap read (ADD 09 §8). It is
not a background job: the finalize endpoint runs it **in-process** within the caller's
transaction. `FinalizeService.finalize_host` (`src/fathom/core/finalize.py`) iterates the
calling host's stale volumes and calls `recompute_full` directly, so the work executes inside
the `api` worker. That worker is hard-capped at `mem_limit: 1g` / `memswap_limit: 1g`
(the deployment stack's `docker-compose.yml`, the `api` service) — swap is disabled, so exceeding the
ceiling is a SIGKILL, not a slowdown.

At estate scale this is a memory problem on both the read and the write side. A single volume
holds millions of `fs_entry` rows (measured: 3.15M live rows on one production volume) rolling up
into hundreds of thousands of directory rows. The original ORM approach OOM-killed the worker
on two counts:

- **Read.** A full `select(FsEntryRow)` consumed under `stream_scalars` still adds every
  mapped instance to the `AsyncSession` identity map. Streaming the cursor bounds the *DB
  client buffer* but not the session — the identity map retained every one of the 3.15M rows
  for the life of the call, so resident memory grew with the entry count.
- **Write.** The write phase added one `SubtreeRollup` ORM object per directory (~636k) via
  the unit-of-work. Each carries a mapped instance plus identity-map / flush state — roughly
  600 MB for 636k rows — materialised before flush.

Either path alone crosses 1 GiB; together they reliably SIGKILL the worker. The rollup is the
only place in the catalogue read/finalize path that touches a whole volume's entries at once
(`_stale_volume_ids` keeps its staleness check to two aggregate sub-selects, no per-entry
scan), so it is the one hot loop that must be made memory-bounded for finalize to survive
estate scale inside the 1 GiB cap.

## Decision

Make `recompute_full` bounded by the *rollup tally* (one accumulator per directory), never by
the entry count, on both sides:

- **Streaming read of raw scalar columns, not the ORM entity.** Select the four scalar
  columns the tally needs — `FsEntryRow.path`, `size_logical`, `size_on_disk`, `is_dir` —
  filtered to `volume_id` and `present.is_(True)`, via `session.stream(...)` with
  `execution_options(yield_per=10000)`. Scalar `Row` tuples are not tracked by the identity
  map, so peak memory is the tally, not the rows; `yield_per` bounds the server-side cursor's
  client buffer so the whole result set is never materialised at once. Filtering to `present`
  means a re-finalize after an incremental pass never lets a soft-deleted entry
  (`present=False`, `removed_at` set) inflate a current subtree total — consistent with the
  `present`/`removed_at` current-state contract in `src/fathom/core/catalogue/models.py`.

- **Chunked Core `insert()` of plain dict batches, not the unit-of-work.** After deleting the
  volume's existing rollup rows (atomic within the caller's transaction), generate the rollup
  rows lazily (`_rollup_rows` yields one dict per accumulated directory) and write them with
  `session.execute(insert(SubtreeRollup), batch)` in batches of 5000 (`_batched`,
  `_ROLLUP_INSERT_CHUNK`). Plain-dict Core insert carries no per-row mapped-instance or
  flush state, so the write phase stays bounded by the batch, not the directory count.

The single `size_history` root point and the snapshot-stat stamping
(`FinalizeService._finalize_snapshot_stats`) keep their ORM `add`/attribute writes — they are
O(snapshots), not O(entries), so they stay off the memory-critical path.

**Measured in the deployed 1 GiB container:** 636,401 rollup rows written in 41s at 355 MiB
peak RSS. The prior ORM approach was SIGKILL near 1 GiB on the same volume.

### Alternatives considered

- **Raise the `api` `mem_limit`.** Rejected. It masks the unbounded growth rather than fixing
  it — memory would still scale with entry count, so the next-larger volume reintroduces the
  OOM, and a bigger cap eats headroom the core host budgets for its other ~62 containers
  (deployment stack `docker-compose.yml` header).
- **ORM `bulk_save_objects` for the write.** Rejected. It skips some unit-of-work overhead but
  still constructs one mapped object per row, so the write phase remains heavy and scales with
  the directory count; Core `insert()` of dicts avoids instance construction entirely.

## Consequences

### Positive

- Finalize survives estate scale inside the existing 1 GiB `api` cap — no infra change, no
  headroom taken from the core host's other containers.
- Peak memory is bounded by the directory tally (~636k accumulators), independent of how many
  `fs_entry` rows the volume holds; the read side adds only a fixed `yield_per` buffer.
- The whole recompute stays in the caller's transaction: the `delete` + chunked `insert`
  replace a volume's rollup atomically, preserving the existing finalize semantics
  (rollups, `size_history`, snapshot stats, and the report-only dedup rebuild all commit
  together).

### Negative

- The read deliberately bypasses the ORM identity map and the write bypasses the
  unit-of-work, so this path hand-builds `Row`-tuple reads and dict rows. It must be kept in
  sync with the `FsEntryRow` / `SubtreeRollup` column sets by hand — the type checker will not
  catch a column rename here as it would on mapped-attribute access.

### Risks

- The `_Acc` tally still holds one accumulator per **directory**, so a pathological volume
  with hundreds of millions of directories could re-pressure the cap. Bounded for the current
  estate (636k directories at 355 MiB leaves comfortable headroom under 1 GiB); the
  ADD 09 §8 incremental recompute of only change-feed-affected ancestor paths — noted as a
  follow-up in `rollup.py` — removes even that ceiling and is the durable fix if directory
  counts grow by an order of magnitude.
- The two batch constants (`_ENTRY_STREAM_YIELD = 10000`, `_ROLLUP_INSERT_CHUNK = 5000`) are
  tuned against the measured profile; a materially different row/directory ratio may warrant
  retuning. They are isolated module constants, so retuning is a one-line change with no API
  impact.
