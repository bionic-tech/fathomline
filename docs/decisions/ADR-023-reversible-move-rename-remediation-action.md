# ADR-023: Reversible MOVE/RENAME remediation action

**Status:** Accepted **Date:** 2026-06-07 **Deciders:** project owner

## Context

Applying an Organize proposal (ADR-021) means **moving and renaming files** into the proposed
tree. Fathom's remediation engine already executes gated, audited, drift-checked, reversible
actions — but only `QUARANTINE` (reversible move to a quarantine tier) and `HARD_DELETE`
(irreversible, extra-gated); `HARDLINK` is designed, not built (`agent/actor/executor.py`,
ADR-011). Organize needs a first-class **move-to-an-operator-chosen-destination** action. It must
fit the existing executor's safety contract exactly so it inherits — rather than re-invents — the
TOCTOU re-check, blast cap, audit-before-act, and step-up MFA.

## Decision

Add **`PlanAction.MOVE`** (rename within or across directories under the same volume) to the
remediation plan + executor, with the same per-item hedging as quarantine and one addition —
**reversibility metadata**:

- **Server-authoritative destination.** The plan item carries the **original** path and the
  **destination** relative path; the destination is clamped to the operator-approved root and
  re-validated server-side (no traversal, no escape, stays within the volume). The agent never
  trusts a client-supplied path (AR-0012).
- **TOCTOU-resistant, fd-anchored.** Exactly as the existing executor: operate on a parent-dir fd
  + name, re-`lstat` and **re-hash** the source through that fd immediately before acting, abort on
  symlink / inode / size / **content-hash** drift (STRIDE T-2). An item with no hash anchor is
  refused for a move just as for a delete — we never relocate bytes we cannot prove are the
  approved ones.
- **No-clobber.** The destination is opened `O_EXCL`-style (refuse if the target name already
  exists); a collision aborts the item rather than overwriting. Missing parent directories in the
  destination are created under the validated root.
- **Same-volume only in v1.** A `renameat` within the volume is atomic; cross-volume moves
  (copy + verify-hash + unlink) are deferred — a move that would cross a filesystem boundary is
  refused, not silently degraded.
- **Reversible.** Audit-before-act records the `(from, to)` pair on the tamper-evident chain
  (ADR-019); the executor returns a `moved` result carrying the prior path, so the same
  restore machinery that un-quarantines can **undo a move**. Reversibility is a first-class
  property, not a manual reconstruction.

`MOVE` is gated identically to `EXECUTE_REMEDIATION` + fresh step-up MFA + the server blast cap +
the default-OFF `remediation_enabled` flag. **Auto-application is never offered** — a human
approves every plan (the suite's standing rule). Tests exercise the executor only against
**throwaway temporary files**, never real data; the dry-run path simulates a full plan with **no
filesystem mutation**.

## Consequences

### Positive
- Organize-apply reuses the entire remediation safety machinery (dry-run, blast cap, MFA, audit,
  scope) — one new action, no new destructive surface or second write path.
- Reversibility makes a wrong reorganisation a one-click undo, not a disaster — the single biggest
  safety property for a bulk-move feature.

### Negative
- A new executor branch + reversibility bookkeeping to maintain and test; the no-clobber and
  parent-creation logic must be exactly right to avoid data loss.

### Risks
- **Same-length in-place content swap between plan and execute** → caught by the fd-anchored
  re-hash gate (T-2), identical to the delete/quarantine path.
- **Destination collision / traversal** → refused (no-clobber + server-side root clamp), covered by
  adversarial tests.
- **Cross-filesystem move treated as atomic rename** → refused in v1 (same-volume only); cross-FS
  copy-verify-unlink is a later, separately-tested action.
- **Partial bulk apply** → each item is independent + audited; a failed item aborts that item only,
  and the reversible record lets the operator roll back what did move.
