# ADR-028 — rclone cloud backend (metadata now; zero-egress dedup deferred)

**Status:** Accepted (phase 1 built) · **Date:** 2026-06-11 · **Deciders:** project owner
**Related:** ADR-004 (storage backends), ADD 02 (walk modes / full-bit boundary), ADR-010
(secrets), ADR-011 (dedup)

## Context

Homelab estates increasingly include cloud storage — Google Drive, S3/B2, Dropbox, OneDrive,
NextCloud-over-WebDAV. The recurring question is "what's up there, how big, and does it duplicate
what's on my NAS?" Two ways to reach it:

1. **FUSE mount + the POSIX backend.** `rclone mount` exposes a cloud remote as a local
   filesystem the existing `PosixBackend` already walks. Works today, but: inode identity is
   unstable across remounts (re-stat churn), and content dedup means *downloading* every candidate
   (egress cost / time).
2. **A native rclone backend** that calls the `rclone` binary directly. The win: `rclone lsjson`
   enumerates a remote (sizes, mtimes, tree) from the provider's listing API — no file downloads —
   and `rclone lsjson --hash` can return **provider-side content hashes** (MD5/SHA-1/QuickXorHash
   the provider already computed), which is the basis for *zero-egress* duplicate detection.

## Decision

Add a first-class, **metadata-only** rclone backend (`fathom/backends/rclone.py`), built in two
phases.

### Phase 1 (built) — metadata walk

- `RcloneBackend` extends the shared `_RemoteBackendBase`, so it inherits the two remote
  invariants: `open_for_hash` **refuses** (full-bit would download the file — ADD 02 line 63) and
  `is_busy` is `False`. It matches by `mount_key` like SMB/SFTP.
- It shells out via `asyncio.create_subprocess_exec` (an **argument vector — no shell**), so a
  config value can never inject a command; the composed `<remote>:<subpath>` target is refused if
  it begins with `-` (rclone would misread it as a flag). The runner is injectable for hermetic
  tests against canned `lsjson` output.
- **Auth is out of band.** Credentials live in the host's `rclone.conf`; the agent config carries
  only the remote *name* (`host`) and a subpath (`remote_path`) — never a secret. A credential
  reference on an rclone target is a config error (fail-closed).
- Cloud objects have no POSIX ownership, so entries are mapped with synthetic uid/gid +
  `synthetic_owner` (the UI must not imply a permission that does not exist), `inode=0`
  (no stable remote inode), and `size_on_disk == size_logical` (no allocation info over the wire —
  capability-honest).

This makes a cloud remote a normal volume in the estate view (dashboard, treemap, largest,
search, growth) and feeds the **size→ stage** of dedup, so cross-host *size-candidate* duplicates
that include cloud files already surface.

### Phase 2a (built) — provider-hash capture + cross-cloud duplicate grouping

Full duplicate *confirmation* needs content hashes. The catalogue's `full_hash` is BLAKE3, but
rclone returns the provider's algorithm (MD5 for Drive/S3, SHA-1 for Dropbox, QuickXorHash for
OneDrive). Built:

- `lsjson --hash` populates `FsEntry.provider_hash` + `provider_hash_algo` (the rclone backend
  picks one algorithm by a fixed preference so a remote that exposes several is consistent);
- the wire `EntryFrame`, catalogue `FsEntryRow` (+ a partial grouping index) and ingest carry them
  (migration `d8f1a3c64e2b`, up/down tested);
- `core/provider_dedup` groups present entries by `(algo, hash, size)` — read-only, like-with-like,
  surfacing cross-cloud duplicates at **zero egress**. `iter_provider_hash_duplicates` yields one
  group at a time (truly bounded memory — the variant for an estate-scale API);
  `find_provider_hash_duplicates` is a convenience wrapper that materializes the list.

**Trust model (load-bearing).** Provider hashes are a *distinct trust class* from `full_hash`:
they ride a **metadata** batch (the agent never read the bytes — the provider computed the hash),
so unlike `full_hash` they are not gated on a `fullbit` batch. They live in their own columns,
are **never conflated** with `full_hash`, and are **report-only — they never drive remediation**
(which keys on the content-verified BLAKE3 `full_hash`). Therefore the worst a forged provider
hash can do is mislead an informational duplicate report, never cause a destructive action — which
is why accepting them on a metadata batch is safe.

### Phase 2b (deferred) — cloud-vs-local + UI

- Cloud-vs-local: recompute the provider's algorithm on the *local* side only for size-collision
  candidates (bounded work), so a cloud object can be matched against a NAS copy.
- Wire `find_provider_hash_duplicates` to a read API route + the Duplicates UI (it ships as a
  tested library function first; the route/UI is the next increment).

## Consequences

- No new Python dependency — the `rclone` binary is an optional, lazily-required external tool
  (absence maps to `MissingClientLibraryError`, the same shape as a missing asyncssh/smbprotocol).
- The metadata walk uses `rclone lsjson --recursive` (one call, provider-paged by rclone). For very
  large remotes this would materialize a large JSON listing, so the subprocess runner **bounds the
  output buffer and fails LOUD past a ceiling** (256 MiB) rather than OOM-ing, and enforces a
  wall-clock **timeout** so a hung listing can't block the agent — both via an incremental,
  deadlock-free concurrent stdout/stderr drain. A genuinely *streaming* reader (`rclone lsf`
  line-by-line, matching the local walk's 50M-entry bounded contract) is the phase-2 improvement;
  the runner is injectable so it can drop in without touching the backend.
- The new subprocess surface was hardened against injection and hostile/corrupt remote output:
  there is no shell and a composed target is refused if it starts with `-` (no reachable command/arg
  injection); and the robustness gaps — no timeout, unbounded buffer, `about()` crash on non-dict
  JSON, and int64 size saturation against corrupted remote metadata — are all fixed and
  regression-tested (hermetic tests drive a tiny real subprocess for the timeout/cap paths and
  stubbed output for the JSON guards).
