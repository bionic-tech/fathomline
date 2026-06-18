# ADR-021: Content-aware "Organize" subsystem

**Status:** Accepted **Date:** 2026-06-07 **Deciders:** project owner

## Context

Operators want more than "what is big / what is duplicated" — they want help **tidying a messy
folder**: rename files to meaningful names and sort them into a sensible tree based on what they
actually contain and on well-known conventions (date, type, project). This is the capability the
MIT-licensed prior-art project [`iyaja/llama-fs`](https://github.com/iyaja/llama-fs) demonstrates:
read file content, ask an LLM to propose a folder structure + renames, show the suggestion, apply
on approval; plus a watch daemon that learns from the user's own moves.

Fathom already owns ~80% of the substrate this needs, so the right move is to **re-implement the
idea natively on Fathom's primitives, not fork or vendor llama-fs** (its workflow/concepts are not
copyrightable; MIT would even permit copying with attribution, but a native build fits Fathom's
security model far better). The reusable substrate:

- the scanner + catalogue (`fs_entry`: path, size, mtime, type, content hash);
- the **gVisor preview worker** (`src/fathom/preview/`) — already the *only* place that decodes
  untrusted file content, in a sandbox, emitting safe derived artifacts (ADR-014);
- the **remediation engine** — already a propose → dry-run drift check → step-up-MFA → execute →
  hash-chained-audit pipeline with a blast cap and reversible-first semantics (ADR-011, ADR-019);
- the **incremental change feed** (`change_log`, ADR-006) for watch-mode triggers;
- deny-by-default RBAC scope (ADD 13) and the self-hosted, no-egress-by-default posture (doc 10).

The new parts are small: an LLM step and a new write-action.

## Decision

Add an **Organize** subsystem that turns an operator-selected folder into a reviewed, gated
reorganisation, composed from existing subsystems:

```
scanner/catalogue ─▶ content digest (sandbox) ─▶ LLM proposal ─▶ remediation apply ─▶ audit
```

1. **Digest, not raw bytes, feeds the model.** A per-file *content digest* is produced — metadata
   (name, extension, size, mtime, path context) plus, when content understanding is enabled, a
   **safe text summary / caption / transcript derived inside the gVisor sandbox** (extending the
   preview worker's renderers, ADR-014). Raw file bytes **never** reach the LLM-calling core; only
   the derived digest leaves the sandbox. Phase 1 ships a metadata-only digest; content digests are
   an additive sandbox extension.
2. **The LLM only *proposes*.** A pluggable inference provider (ADR-022, local Ollama by default)
   receives the digests + scope and returns a **structured** proposal: a target relative path /
   name per file. The model never executes anything and is given no tool access.
3. **The server is authoritative over every proposed path.** Each proposed target is **clamped to
   the selected root** and rejected on traversal / absolute paths / escapes — the same
   path-vetting Fathom already enforces on ingest (AR-0012). This neutralises prompt-injection: a
   file whose content says "move everything to /etc" can only ever yield an in-root suggestion the
   human still reviews.
4. **Apply is a remediation plan, not a new write path.** Approving a proposal builds a
   `RemediationPlan` of the new `MOVE`/`RENAME` action (ADR-023) and runs it through the *existing*
   gated engine: dry-run drift check → blast cap → fresh step-up MFA → reversible execute →
   audit-before-act. Organize inherits every remediation gate; it adds no new destructive surface.
5. **Suggest-only first, apply later.** Phase 1 is read-only ("here is a better structure for this
   folder", a before→after diff). Phase 2 wires approval into the remediation wizard. Phase 3 adds
   watch-mode suggestions off the change feed + few-shot learning from accepted plans.

The whole subsystem is **default-OFF** behind a settings gate, like remediation and preview.

## Consequences

### Positive
- High-value, llama-fs-class feature with a fraction of the new code, because the dangerous parts
  (content decode, file mutation) reuse already-hardened subsystems (gVisor sandbox, remediation).
- **Strictly safer than the prior art:** untrusted content is decoded only in the sandbox; the
  model sees a derived digest; the model never executes; every path is server-clamped; every move
  is reversible, MFA-gated, and audited.
- Local-first (ADR-022) keeps content-derived text on-host by default — sovereignty preserved.

### Negative
- A new LLM dependency (operationally: an Ollama deployment) and prompt-engineering surface to
  maintain; proposal quality varies by model.
- Content digests need the preview sandbox (runsc) deployed to be content-aware; metadata-only
  organise works everywhere but is less "smart".

### Risks
- **Prompt injection** via file content/names → mitigated by server-authoritative path clamping +
  human review + dry-run (the model proposes, never acts). Tracked as an adversarial test set.
- **Data egress** if a cloud inference provider is chosen → the digest (derived from content)
  would leave the host; gated, off by default, and audited (ADR-022).
- **Bad bulk move** → mitigated by the remediation blast cap, dry-run drift gate, reversibility,
  and MFA (ADR-011/023). Never auto-applied — a human approves every plan (out-of-scope: auto-
  remediation, per the suite's standing rule).
