# ADR-019: Tamper-evident audit chain hardening (fork-proof + signed checkpoints)

**Status:** Accepted **Date:** 2026-06-06 **Deciders:** project owner

## Context
Remediation is the only data-destroying surface (ADR-011), and its discipline is
**audit-before-act** — no audit record, no action (`src/fathom/core/audit.py`; ADD 02 §Mode 3,
ADD 03 §8). The audit is a hash-chained, append-only log: each `AuditRecord.row_hash` covers the
previous record's hash plus the canonical payload (`compute_row_hash`, `src/fathom/core/audit.py`),
so altering or removing any record breaks every hash after it and `verify_chain` detects it.
`RemediationAuditRow` (`src/fathom/core/remediation/models.py`) persists the chain so the head
survives restarts and the sequence is one unbroken line across the deployment lifetime, not
per-process (`load_head`, `build_persistent_chain`, `src/fathom/core/audit_store.py`).

Three gaps surfaced in security review of the persisted store, all turning on the same property —
the log must remain a single, complete, verifiable line that no writer or operator can fork,
truncate, or silently rewrite:

1. **Forking under concurrency.** The chain head lives on the in-process `AuditChain` after it is
   seeded from the last row, and every `append` advances it. Two writers that resume the *same*
   head and both append produce two rows with the *same* `prev_hash` — a fork into two siblings.
   An in-memory `AuditChain` alone cannot arbitrate between two processes racing the live head.
2. **The destructive act on a volatile sink.** The actor's executor records its per-item mutation
   audit via an in-memory `AuditChain` whose `sink` is volatile; if only that copy held the record
   of the act, the destructive operation itself would not be on the tamper-evident, persisted store.
3. **Tail truncation / rewrite of anchored rows.** `verify_chain` proves a *given* list of rows is
   internally consistent, but cannot by itself prove rows were not dropped from, or rewritten in,
   the persisted store — there is no external commitment to compare the live head against
   (security-architecture §11 OQ3).

The persisted store already denies the API DB role UPDATE/DELETE on the audit tables at the grant
layer (`src/fathom/core/remediation/models.py` docstring; enforced in production), but the chain
must also be self-defending at the data-model and verification level, fail-closed.

## Decision
Harden the persisted audit chain along three axes, all evidenced in
`src/fathom/core/audit_store.py`, `src/fathom/core/remediation/models.py`, and exercised by
`tests/core/test_audit_store.py`.

**1. The DB is the fork arbiter — UNIQUE `prev_hash`.** `RemediationAuditRow.__table_args__`
carries both `UniqueConstraint("row_hash", name="uq_remediation_audit_row_hash")` **and**
`UniqueConstraint("prev_hash", name="uq_remediation_audit_prev_hash")`. The UNIQUE `prev_hash`
means **only one row may ever point at a given predecessor**: two concurrent appends off the same
head produce two rows with the same `prev_hash`, and the DB admits exactly one. `append_durable`
builds the record off the current head and flushes it inside a `session.begin_nested()` SAVEPOINT;
on the loser's `IntegrityError` it reloads the head (`load_head`) and re-chains onto the
now-advanced head, retrying up to `_MAX_APPEND_RETRIES` (8) before failing closed with a
`RuntimeError`. The bound stops a pathological hot row from spinning forever. The result is one
linear chain, never a fork. This mirrors the `used_nonce` UNIQUE-constraint arbiter for replay
rejection (T-3) — the database, not application code, resolves the race.
`test_duplicate_prev_hash_insert_is_rejected` proves the forked sibling INSERT is rejected;
`test_append_durable_retries_fork_into_linear_chain` and
`test_append_durable_reloads_head_after_external_write` prove the retry yields a single verifiable
line chained onto the live head.

**2. Re-chain the actor's in-memory audit onto the durable head.** `append_records_durable` takes
the `AuditRecord`s the actor's executor built in memory (`src/fathom/agent/actor/executor.py`) and
splices each onto the persisted chain's live head via `_splice_record_durable`: `rechain`
(`src/fathom/core/audit.py`) recomputes `prev_hash`/`row_hash` against the current head while
preserving the content fields verbatim — including the actor's original `ts` — and the splice goes
through the same fork-rejection + retry path as `append_durable`. So the destructive act itself
lands on the tamper-evident, hash-chained store, not only the actor's volatile sink, and a
concurrent core writer cannot fork the chain during the splice.

**3. Periodic signed checkpoints anchor the head.** `write_checkpoint` records
`(seq, row_hash, signature, key_id)` for the last persisted row into `RemediationAuditCheckpointRow`,
signing the canonical bytes `f"{seq}:{row_hash}"` (`_checkpoint_message`) with a `CheckpointSigner`.
The signer/verifier are a distinct protocol from the action-job `Signer` (a checkpoint signs head
bytes, not an `ActionJob`); the `Ed25519CheckpointSigner`/`HmacCheckpointSigner` and their verifiers
in `src/fathom/core/remediation/signing.py` satisfy it, with key material from the pluggable secret
backend (ADR-010), never from code. `verify_latest_checkpoint` fails closed (returns `False`)
unless all three hold: the checkpoint signature is valid over its `(seq, row_hash)` (not forged); a
row at that `seq` still carries that `row_hash` (the anchored row was not rewritten); and the live
chain up to `seq` is an unbroken `verify_chain` with at least `seq` rows (nothing at or before the
anchor was dropped). Dropping rows *after* the anchor is benign for this check — a fresh checkpoint
advances the anchor — but dropping or rewriting the anchored row, or any row before it, is caught.
With no checkpoint yet, there is nothing to extend, so it returns `True` vacuously; callers that
*require* an anchor gate on "has a checkpoint" separately. Checkpointing is never on an action's
critical path — staged onto the session and committed by the caller, returning `None` on an empty
(genesis) chain. The checkpoint tests (`test_checkpoint_written_and_verifies`,
`test_checkpoint_rejects_forged_signature`, `test_checkpoint_detects_rewritten_anchored_row`,
`test_checkpoint_detects_truncation_before_anchor`) cover each failure mode.

**Alternatives rejected.**
- *Indexed-but-not-UNIQUE `prev_hash`.* An index speeds head lookups but does not constrain
  cardinality, so two siblings with the same `prev_hash` both commit — the chain forks. Rejected:
  it does not make the DB the arbiter, which is the whole point of fix (1).
- *Application-level locking around append* (in-process mutex / advisory lock). Not crash-safe: a
  writer holding the lock that dies mid-append leaves the head ambiguous, and an in-process lock
  does not span sessions resuming the same head. Rejected in favour of the database resolving the
  race atomically (same rationale as the `used_nonce` arbiter).

## Consequences

### Positive
- The persisted audit can never fork: UNIQUE `prev_hash` admits exactly one successor per
  predecessor, so the log is always a single linear chain even under concurrent appends — proved by
  `test_append_durable_retries_fork_into_linear_chain`.
- The destructive act is on the tamper-evident store, not only the actor's in-memory sink
  (`append_records_durable` / `_splice_record_durable`), closing the audit-completeness gap for the
  mutation itself.
- Truncation and silent rewrite of anchored rows are detectable against an external, signed
  commitment (`verify_latest_checkpoint`), addressing security-architecture §11 OQ3.
- The arbiter is the database, atomically and crash-safely, consistent with the `used_nonce`
  replay-rejection design (T-3) — no new locking primitive to reason about.
- Fail-closed throughout: a fork retry that cannot win after `_MAX_APPEND_RETRIES` raises rather
  than writing a fork; a failed checkpoint or chain verification returns `False`; and because
  audit-before-act writes the row before the mutation, a failure to persist the audit aborts the
  action — there is no path that mutates without a chained audit row.

### Negative
- The UNIQUE `prev_hash` constraint serialises appends at the head: under contention, losers burn a
  SAVEPOINT round-trip plus a head reload per retry, so a hot chain pays latency to stay linear.
- Checkpointing adds a signer dependency and key material to manage (ADR-010 rotation), plus a
  second audit table (`remediation_audit_checkpoint`) and its migration.
- `verify_latest_checkpoint` loads the chain up to `seq` via `persisted_records` to re-verify it;
  for a very long chain this is an O(n) read, so checkpoint verification is an audit/operational
  action, not a per-request hot path.

### Risks
- **Retry exhaustion under pathological contention** — a permanently hot head could exhaust
  `_MAX_APPEND_RETRIES` and fail the action closed. Mitigated by the bound being generous for the
  single-operator v1 (ADR-011) and by appends being short; raising the bound or backing off is a
  follow-up if multi-writer contention ever materialises.
- **Checkpoint key compromise** — an attacker with the checkpoint signing key could forge an anchor
  matching a rewritten head. Mitigated by sourcing key material from the secret backend (ADR-010),
  never code, and by `key_id` binding; key rotation/escrow for the checkpoint key is a follow-up.
- **Tail truncation between checkpoints** is undetectable by `verify_latest_checkpoint` alone (it
  only proves the live head still extends the *last* anchor). Mitigated by checkpoint cadence;
  tighter coverage (e.g. anchoring on every Nth row or on dispatch) is a follow-up.
- **Append-only relies on the grant layer** for UPDATE/DELETE denial in production; the data-model
  and verification hardening here detects rewrites but does not by itself prevent a privileged
  operator with direct DB access from rewriting and re-checkpointing — defence in depth with the
  ADR-011 separation of duties and the production grant.
