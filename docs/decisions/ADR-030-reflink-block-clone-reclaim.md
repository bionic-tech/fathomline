# ADR-030: Zero-deletion reclaim — reflink / block-clone remediation action

**Status:** Proposed · **Date:** 2026-06-11 · **Deciders:** project owner
**Related:** ADR-011 (remediation enabled in v1, guarded), ADR-023 (reversible MOVE action),
ADR-004 (`StorageBackend` Protocol), ADR-008 (read-only `PlatformAdapter`), ADD 02 §Mode 3
(guarded executor), STRIDE T-2/T-3, E-1

## Context

Fathom's remediation engine already turns a content-confirmed duplicate group into a gated,
audited, drift-checked action. Today the dedup spine offers three dispositions for a duplicate
copy, each ranked by how much it costs the operator if the keep/remove choice was wrong:

- **`QUARANTINE`** — a reversible `renameat` into a quarantine tier, the default
  (`agent/actor/executor.py:242`). The bytes still exist; the path stops working until restored.
- **`HARD_DELETE`** — irreversible `unlink`, behind the extra `allow_hard_delete` flag and a
  refusal to act on any item with no hash anchor (`agent/actor/executor.py:235`, `:250`). The
  bytes are gone; the path stops working forever.
- **`HARDLINK`** — designed but never built; the v1 spine returns `skipped_disabled` for it
  (`agent/actor/executor.py:257`). It would share an inode, but two paths sharing one inode also
  share permissions, ownership, and a destructive truth: editing "one" copy mutates "both", and
  any tool that does an atomic-replace-by-rename quietly breaks the link.

Every one of these makes a path *stop being a normal, independent, writable file* in exchange for
space. That is the fundamental cost. For a large class of real estates — VM images, backup
chains, media masters, container layers, dataset snapshots that legitimately have many identical
copies under different owners — the operator does not want to choose a keeper and demote the rest.
They want the bytes stored once **while every path keeps working exactly as before**: same inode-
level independence, same permissions, same "edit this copy, the other is untouched" semantics,
writable, no quarantine tier to remember to restore from.

Modern filesystems give exactly that primitive: **copy-on-write block sharing**. ZFS 2.2+ block
cloning and BTRFS/XFS reflinks (the `FICLONE`/`FICLONERANGE` ioctls, surfaced portably by
`copy_file_range`) let two independent files point at the *same physical extents* until one is
written, at which point only the changed blocks diverge. The duplicate's logical bytes still
exist and are still readable/writable through its own path; the filesystem simply stops storing a
second physical copy. This is **zero-data-loss space reclaim** — strictly safer than delete
because *neither* path is destroyed, and reversible by definition (a subsequent write to either
side just re-allocates, the way it always would).

Fathom already *observes* this property: the ZFS backend sets `flags["reflink"]` when a file's
allocated bytes under-count its logical size because blocks are shared
(`backends/zfs.py:179`–`:181`), and the flag vocabulary documents `"reflink"` as "block-shared /
CoW extent; on-disk bytes are shared, not unique" (`backends/base.py:29`). What is missing is the
*remediation* direction: deliberately turning two distinct, identical files into one shared-extent
pair. This ADR designs that action. **It is a design, not an implementation** — nothing here is
built; the consequences section gives the phased plan and the gate it must clear first.

## Decision

Add **`PlanAction.REFLINK`** (working name; block-clone/reflink the duplicate against the keeper)
as a new remediation action that rides the **existing** signed, audited, drift-checked write path
— it inherits, rather than re-invents, every safety property. Like ADR-023's `MOVE`, it is one new
branch in the executor's `_mutate` dispatch (`agent/actor/executor.py:239`–`:258`), not a second
write path.

### Reuses the BLAKE3 keeper/duplicate model unchanged

A `REFLINK` plan is built from the **same content-confirmed duplicate group** every reclaim action
uses. The group is formed only when two or more catalogue rows share the **full BLAKE3
`full_hash`** (and size), never a size- or partial-hash match (`core/dedup_service.py:206`,
`:213`–`:216`). `build_plan` stamps that `full_hash` onto every item as its `prior_hash`
anchor (`core/remediation/plan.py:91`–`:92`), and the keeper is the operator's **explicit**
`keep_id` — Fathom never auto-selects (`core/remediation/plan.py:83`–`:85`, ADR-011). The
non-binding suggested-keeper rule (oldest → preferred volume/path → shortest path,
`core/dedup_service.py:91`) is advisory only.

Crucially, `REFLINK` keys on the **content-verified BLAKE3 `full_hash`** exactly as
`QUARANTINE`/`HARD_DELETE`/`MOVE` do — and **never** on the report-only provider hash. The
provider-hash duplicate grouping (`core/provider_dedup.py`) is a weaker, provider-trusted signal
that "these objects look identical per the cloud provider"; it is documented as report-only and
forbidden from feeding the remediation/keeper path (`core/provider_dedup.py:9`–`:12`,
`backends/base.py:92`–`:99`). A reflink shares *physical bytes on the keeper's disk*; it would be
indefensible to do so on anything less than a byte-for-byte content match the agent itself
computed. So `REFLINK`, like every reclaim action, is gated on `full_hash` and is a strictly
**local, same-host, same-filesystem** action — it can never be offered for a provider-hash group
or a remote/cloud volume (see §Filesystem mechanics).

### Rides the existing remediation gates verbatim

`REFLINK` is gated **identically** to the other destructive actions — same route, same caps, same
MFA, same audit — because it touches the keeper's on-disk blocks and replaces the duplicate's
content with a clone:

- **Default-OFF, two layers.** The API route refuses unless the server `remediation_enabled` flag
  is on (`api/routers/remediation.py:68`–`:74`); the agent executor refuses unless
  `write_enabled` is True (`agent/actor/executor.py:137`–`:140`). Defence in depth, as today.
- **Capability + step-up MFA + danger-zone confirm.** Build needs `BUILD_REMEDIATION`; execute
  needs `EXECUTE_REMEDIATION` **plus fresh step-up MFA** (`api/routers/remediation.py:386`–`:391`)
  **plus** the operator typing the target host name (`api/routers/remediation.py:423`–`:427`).
  `REFLINK` adds nothing new here — it uses `EXECUTE_REMEDIATION` like the others.
- **Server-authoritative blast cap.** The orchestrator refuses an execute over the cap without an
  explicit `confirm_blast` (`core/remediation/orchestrator.py:220`–`:224`), and the executor
  re-checks it agent-side (`agent/actor/executor.py:143`–`:147`).
- **Dry-run-first, non-drifted subset only.** Execute mandatorily dry-runs first and dispatches an
  EXECUTE job for only the non-drifted items (`core/remediation/orchestrator.py:210`,
  `api/routers/remediation.py:455`–`:463`). A drifted item is dropped, never acted on (T-2).
- **Signed single-use job.** The action set is wrapped in a signed, nonce'd, time-boxed
  `ActionJob` whose signature covers every `PlanItem` (`core/remediation/job.py:30`–`:87`); the
  actor verifies signature + nonce + expiry + scope before any filesystem access (T-3).
- **Audit-before-act on the tamper-evident chain.** The executor writes a `pending` audit record
  *before* the mutation and a result record after (`agent/actor/executor.py:182`–`:201`), and the
  orchestrator splices the actor's per-item mutation audit onto the durable hash-chained store so
  the act itself lands on the fork-proof log (`core/remediation/orchestrator.py:240`–`:253`,
  `core/remediation/models.py:134`–`:159`). No audit, no action.

### TOCTOU-safe executor — resolve-and-reverify, `O_NOFOLLOW`, operate on fds

`REFLINK`'s `_mutate` branch obeys the **same** TOCTOU contract as every other action, with one
addition: it must re-verify **both** ends (the keeper it clones *from* and the duplicate it
replaces). For the **duplicate** side, the existing per-item recheck applies unchanged
(`agent/actor/executor.py:206`–`:237`): open the parent directory fd `O_RDONLY|O_DIRECTORY`, then
`lstat` the name **through that fd**, abort on a symlink, on inode change, on size change, and —
the gate inode+size cannot give — on a full-content-hash change re-read **through the same
validated fd with `O_NOFOLLOW`** (`agent/actor/executor.py:41`–`:59`, `:228`–`:234`). The path is
never re-resolved, so there is no second TOCTOU window. An item whose `prior_hash` is `None` is
refused for `REFLINK` exactly as it is for `HARD_DELETE` (`agent/actor/executor.py:235`) — we
never share bytes we cannot prove are the approved, content-identical ones.

For the **keeper** side, `REFLINK` adds a symmetric re-verification: the keeper is opened via its
own parent-dir fd + `O_NOFOLLOW`, re-`lstat`'d, and **re-hashed through that fd** against the same
group `full_hash` immediately before the clone. The clone is then performed **on the two open
fds** — `FICLONE`/`FICLONERANGE` and `copy_file_range` both operate on file descriptors, not paths
— so the bytes the kernel shares are exactly the bytes the recheck validated. A planted symlink, a
swapped inode, or a same-length in-place content swap on either side aborts the item before the
ioctl runs (STRIDE T-2). The keeper's `full_hash` and `(host, volume)` are server-authoritative
from the catalogue (`api/routers/remediation.py:138`–`:177`), never client-supplied (AR-0012).

The replace is staged **atomically and non-destructively**: clone the keeper's extents into a new
temp file in the duplicate's own directory (same parent-dir fd), copy across the duplicate's
metadata (mode/owner/timestamps), `fsync`, then `renameat` the clone over the duplicate's name.
The original duplicate inode is only ever superseded by an atomic rename of a fully-written,
content-verified clone — there is **no window in which the path is missing or truncated**, and a
failure at any step leaves the original duplicate untouched (fail-closed; see §Failure modes).

## Filesystem mechanics & capability gating

A reflink/block-clone shares physical extents between two files on the **same filesystem**. The
three target filesystems and their constraints:

### ZFS 2.2+ block cloning

ZFS gained the `block_cloning` pool feature in OpenZFS 2.2. With it enabled, a clone (via
`FICLONE`/`copy_file_range`) makes the destination reference the source's already-written records
through the Block Reference Table; the blocks become physically shared until one side is written.
Constraints and a hard caveat:

- **Same pool / same dataset constraints.** Block cloning operates within a pool; clones across
  datasets in the same pool work but recordsize and encryption-key boundaries can force a fallback
  to a real copy. The executor treats *same-dataset* (same `Volume.dataset`,
  `core/catalogue/models.py:73`) as the safe v1 target and refuses cross-dataset clones rather than
  silently degrading to a copy.
- **The historical block-cloning corruption bug — min-version guard.** Early OpenZFS 2.2.0
  shipped a block-cloning-adjacent data-corruption bug (the dirty-dnode/hole issue made visible by
  block cloning), fixed in 2.2.2. Because Fathom would be *deliberately invoking* the clone path,
  it must **fail closed on any ZFS below a known-good minimum** (≥ 2.2.2, exact floor pinned at
  build time) and require `block_cloning` to be `active`. The version/feature floor is a hard,
  regression-tested refusal — never a config flag an operator can override into a corrupting
  kernel. This mirrors how the resilver guard fails closed on an unhealthy or unreadable pool
  (`backends/zfs.py:115`–`:134`).

### BTRFS & XFS reflinks

BTRFS (CoW-native) and XFS (with reflink-enabled, the mkfs default for years) support the same
`FICLONE`/`FICLONERANGE` ioctls and `copy_file_range`. They have no equivalent of the ZFS 2.2.0
corruption episode, but they carry their own constraints:

- **Same filesystem (same `st_dev`) — hard requirement.** A reflink cannot cross a filesystem
  boundary. Fathom already carries `st_dev` on every entry as `FsEntry.dev`
  (`backends/posix.py:243`–`:247`) and in the catalogue identity `(host_id, volume_id, dev, inode)`
  (`core/catalogue/models.py:172`–`:176`). The planner refuses a `REFLINK` pairing whose keeper and
  duplicate do not share `dev` — the cross-FS case `copy_file_range`/`FICLONE` rejects with
  `EXDEV`/`EOPNOTSUPP`, exactly as ADR-023's `MOVE` refuses a cross-filesystem `link`
  (`agent/actor/executor.py:291`–`:298`, ADR-023 "Same-volume only").
- **Block alignment.** `FICLONERANGE` requires the cloned range to be block-aligned (the tail may
  need a real copy). For whole-file dedup of byte-identical files this is naturally satisfied
  except possibly a final partial block; the executor uses whole-file `FICLONE`/`copy_file_range`
  semantics and lets the kernel/glibc handle the unaligned tail, never hand-rolling range math.

### Detection — capability reported per volume by the backend/topology layer

Capability is a **per-volume** fact reported by the `StorageBackend`/topology layer (ADR-004,
ADR-008), never assumed and never trusted from a client. The `Volume` row already records
`fs_type`, `device`, `pool`, and `dataset` (`core/catalogue/models.py:68`–`:73`), and the ZFS
backend already detects ZFS via `/proc/mounts` and prefers the authoritative `PlatformAdapter` for
pool topology (`backends/zfs.py:68`–`:74`, `:76`–`:113`). The design adds a small, advisory
**`reflink_capable` capability probe** to `volume_info`:

- ZFS: `block_cloning` feature `active` on the pool **and** kernel/module version ≥ the pinned
  floor — taken from the read-only adapter where available (ADR-008), falling back to a
  capability-honest "unknown → not capable" rather than guessing (`backends/zfs.py:82`–`:99`).
- BTRFS/XFS: `fs_type` plus a cheap, side-effect-free clone probe (a zero-length `FICLONERANGE`
  between two throwaway temp fds on the volume) at volume-registration time — the empirically
  correct way to know reflink works, since XFS reflink is an mkfs-time choice.

The probe result is surfaced as advisory capability the orchestrator consults at **build** time:
a `REFLINK` plan is only ever offered/built for a group whose members live on a reflink-capable
volume, and is re-checked **fail-closed** at the actor immediately before the ioctl (the actor is
authoritative — capability can change between build and act). This is the same "advisory hint in
the catalogue, authoritative re-check at the edge" pattern the existing `flags["reflink"]` already
follows (`backends/base.py:29`, `backends/zfs.py:170`).

## Failure modes & fallbacks

The governing rule, identical to ADR-023's "refused, not silently degraded": **on any failure,
fail closed and leave both files exactly as they were. There is never a destructive fallback.**

- **Not same filesystem (`EXDEV`).** Refused at plan-build (different `dev`) and again at the
  actor; the ioctl's `EXDEV`/`EOPNOTSUPP` is caught and the item returns an `aborted` status, the
  duplicate untouched — mirroring the `MOVE` cross-FS refusal (`agent/actor/executor.py:297`–
  `:298`).
- **Filesystem without reflink / capability unknown.** Refused at build (not reflink-capable) and
  fail-closed at the actor. ext4 and other non-CoW filesystems are simply never offered `REFLINK`;
  the operator still has `QUARANTINE`/`HARD_DELETE` for those.
- **Kernel / version gaps (notably ZFS < floor).** The min-version + `block_cloning=active` guard
  refuses outright; the action is reported unavailable rather than attempted on a possibly-
  corrupting kernel.
- **Partial clone / block-alignment / mid-operation error.** Because the executor writes a fresh
  temp clone and only atomically renames it over the duplicate **after** a successful, fully-
  written, re-verified clone, any partial clone is discarded with the temp file; the original
  duplicate inode is never touched until the atomic rename succeeds. There is no truncated or
  half-shared end state.
- **Drift on either end between plan and execute.** Caught by the dry-run re-verify
  (`agent/actor/planner.py:35`–`:66`) and the actor's fd-anchored recheck of *both* keeper and
  duplicate (`agent/actor/executor.py:206`–`:237`); the item is dropped (T-2). A `prior_hash` of
  `None` is refused (`agent/actor/executor.py:235`).
- **Crash mid-action.** Audit-before-act records intent first (`agent/actor/executor.py:182`–
  `:191`); a crash before the atomic rename leaves the duplicate intact and a `pending` audit row
  the operator can reconcile. There is no irrecoverable intermediate state.

Notably, unlike `HARD_DELETE`, **a failed `REFLINK` costs the operator nothing** — both files
still exist and still work. The worst-case outcome of any failure is "no space reclaimed", not
"data lost".

## Safety argument

`REFLINK` is **strictly safer than delete**, and the argument is structural, not procedural:

1. **Both paths remain valid, independent, writable files.** Unlike `QUARANTINE` (path stops
   working until restored), `HARD_DELETE` (path gone forever), or `HARDLINK` (paths become one
   inode with shared writes/perms), a reflinked pair are two ordinary files. Reading either yields
   identical bytes; **writing either is copy-on-write** and diverges only the changed blocks,
   leaving the other path byte-for-byte unchanged. No operator workflow, permission, or tool
   behaviour changes.
2. **The bytes are deduplicated by the filesystem, not by Fathom.** Fathom does not decide which
   copy "wins" and destroy the other; it asks the kernel to store the shared extents once. The
   logical content of every path is preserved.
3. **Reversible by definition.** There is no "undo" to engineer (as ADR-023 had to for `MOVE`):
   writing to either file simply re-allocates, restoring full physical independence as a normal
   side effect of normal use. The shared state is the *resting* state, and any write naturally
   exits it.

And yet **it still requires the full remediation gate.** The action touches the keeper's on-disk
blocks and atomically rewrites the duplicate's inode content; a forged job, a TOCTOU swap, or a
capability mis-detection could still cause harm (e.g. cloning the wrong source over a file, or
invoking the corrupting ZFS path). So it inherits default-OFF, step-up MFA, blast caps, dry-run-
first, signed jobs, and audit-before-act with **no relaxation** — being "non-destructive" is not a
licence to skip the controls that make *which bytes get shared* provable and non-repudiable.

It **also requires a dedicated adversarial security review before shipping**, exactly as ADR-011
demands of the write path ("the write path must clear **zero open P0/P1** before release") and
ADR-014 required for previews. New surface to review specifically: the keeper-side re-verification
and fd-anchored clone (a *second* TOCTOU surface the existing single-target actions don't have);
the capability probe (must be side-effect-free and unspoofable); and the ZFS version floor (must
be a hard refusal, not an override). Each ≥ P2 finding gets a named regression test (ADR-011).

## Consequences

### Positive

- A genuinely **zero-data-loss** reclaim option: the operator can dedup VM images, backups, media,
  and dataset copies without ever choosing a keeper to demote or remembering a quarantine tier.
- Reuses the **entire** remediation safety machinery — one new `_mutate` branch + a capability
  probe, no new destructive write path, no new route, no new gate (the ADR-023 precedent).
- Strictly dominates `HARD_DELETE` and `HARDLINK` on safety for the cases it covers, lowering
  the temptation to use the irreversible action.

### Negative

- A **second TOCTOU surface** (keeper *and* duplicate) and a more involved atomic-replace dance
  than the single-target actions — must be exactly right, and is the focus of the required review.
- Filesystem- and version-specific capability detection to build, probe, and keep honest; the ZFS
  version floor must track upstream fixes.
- Space reclaimed is **not** the same as space freed on delete: shared extents only fully release
  when *all* referencing files are removed, which can surprise capacity reporting (the existing
  `flags["reflink"]` "do not sum allocated bytes" caveat applies — `backends/zfs.py:170`,
  `backends/base.py:29`).

### Risks

- **ZFS 2.2.0-class corruption if the version floor is wrong or bypassable** → hard, regression-
  tested min-version + `block_cloning=active` guard, fail-closed, no override.
- **Wrong-source clone / TOCTOU on either end** → fd-anchored re-`lstat` + re-hash of *both* keeper
  and duplicate through `O_NOFOLLOW` parent-dir fds, clone on fds, abort on any drift (T-2).
- **Capability mis-detection (claiming reflink where it will silently full-copy or fail)** →
  advisory at build, authoritative fail-closed re-check at the actor; probe is side-effect-free.
- **Operator confusion about reclaimed-vs-freed bytes** → UI labels reflink reclaim distinctly and
  reuses the existing shared-extent caveat.

### Phased plan

- **P1 — ZFS 2.2.2+ block cloning, same dataset, whole-file.** The highest-value target on the
  reference estate (`tank` on `nas-1`/`node-1`); version-floor guard, capability probe via the
  read-only adapter, the keeper+duplicate fd-anchored executor branch, dry-run + audit + tests.
  **Gated behind the dedicated adversarial review and default-OFF**, as ADR-011 requires.
- **P2 — BTRFS & XFS reflink.** Same executor branch via `FICLONE`/`FICLONERANGE`/`copy_file_range`
  + the empirical clone probe at volume registration; same-`st_dev` enforcement.
- **P3 (later) — cross-dataset (same pool) ZFS, and a "reflink-or-skip" bulk mode** that reflinks
  every capable member of a group and reports the rest, never falling back to a copy or delete.

### Out of scope

- **Any cross-filesystem or cross-host clone.** Reflink is same-`st_dev`, same-host only; cross-FS
  is refused, not degraded.
- **Remote/cloud volumes (ADR-028/029) and any provider-hash group.** `REFLINK` is a local,
  same-filesystem, BLAKE3-`full_hash`-only action; the report-only provider hash never reaches it
  (`core/provider_dedup.py:9`–`:12`).
- **Server-side `copy_file_range` over a network filesystem** (NFS server-side copy) — out; full-
  bit reads and clones run only on the host that owns the data (ADR-002, `backends/base.py:52`–
  `:60`).
- **Automatic / unattended reflinking.** A human approves every plan; no auto-application (ADR-011).
- **Building `HARDLINK`.** Orthogonal; this ADR does not revive it.
