# ADR-024: Cross-host reconciliation (divergence detection)

**Status:** Accepted **Date:** 2026-06-09 **Deciders:** project owner

## Context

Dedup (ADR-011) answers "where are byte-identical copies across the estate?" — it groups files by
full content hash, so a group is, by construction, *exactly the same bytes*. But operators also need
the inverse question when they believe two trees on different hosts are **copies of one source**
(e.g. a Nextcloud data directory copied to nas-1, node-1, and node-2): **"treating host X as the
definitive version, which files match, which are the same content but with mangled timestamps, and
which have actually DIVERGED (different size or different checksum) so I should investigate?"**

Dedup cannot express this: a diverged file (different content) simply isn't in any shared group, so
it's invisible. Reconciliation is a *path-aligned* comparison, not a *content-aligned* grouping.

## Decision

Add a **read-only cross-host reconciliation** surface. Given a **definitive** `(volume, root)` (the
operator's source of truth) and a **comparison** `(volume, root)`, match files by their path
**relative to each root** and classify every pair:

- **`identical`** — same size, same `full_hash`, same mtime.
- **`content_same_meta_diff`** — same `full_hash`, but mtime differs (a copy artifact: the bytes are
  identical, only the timestamp drifted — benign, the operator's "same checksum, different dates").
- **`diverged`** — different `full_hash`, or different size with at least one side unhashed → the
  content actually differs; **flag for checking**.
- **`size_match_unhashed`** — same size but one/both sides lack a `full_hash` (metadata-only scan):
  content can't be confirmed → run a full-bit scan to resolve. Surfaced, never assumed identical.
- **`missing_on_comparison`** / **`missing_on_definitive`** — present on only one side.

It returns a **per-class count summary** plus a bounded sample of the actionable items
(diverged / missing first). Classification + counts run **DB-side** (two LEFT JOINs on the computed
relative path — portable across PostgreSQL and SQLite, no `FULL OUTER JOIN`) so it scales to
multi-million-file trees without loading them into the app.

It is **server-authoritative + scope-gated** exactly like every other read: both volumes are
scope-checked, both roots are normalised and confined to their volume mountpoint (reusing the
ADR-021 root-anchor validation), and a non-`full_hash` comparison degrades to `size_match_unhashed`
rather than a false `identical`. It is **read-only** — it proposes nothing and moves nothing; acting
on a divergence is the operator's job (delete/keep via the existing dedup/remediation flow, or an
out-of-band copy).

## Consequences

### Positive
- Answers the real operator question ("is nas-1's copy the good one, and what drifted?") that dedup
  structurally cannot, reusing the existing catalogue + `full_hash` with no new scan type.
- Cheap and safe: a read-only SQL aggregation; no new write surface, no model authority.
- Composes with dedup: identical files are also dedup candidates; diverged files are precisely what
  dedup *hides*.

### Negative
- Only as good as the hashes: a meaningful content verdict needs **full-bit** scans on both sides
  (ADR-002); metadata-only data yields `size_match_unhashed`, not a content answer.
- Path-alignment assumes the two trees share a relative structure (copies). It is not a fuzzy/rename-
  aware diff — a moved/renamed file reads as missing-on-one-side + new-on-the-other.

### Risks
- A huge tree comparison is a heavy DB aggregation → bounded by the same scope/▼ root confinement and
  a result cap (counts are exact server-side; the item list is sampled and marked truncated).
