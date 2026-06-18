# ADR-025: Production agent-initiated signed-job dispatch channel

**Status:** Accepted (as-built) **Date:** 2026-06-09 **Deciders:** project owner

> **As-built note (2026-06-09).** Build steps 1–6 are implemented, default-OFF, gate-green, with a
> two-lens adversarial review and all findings fixed (see *As-built summary* at the foot of this
> ADR). Step 7 — provisioning the live key and enabling a host — is **deliberately not done**; it
> is the operator's separately-authorised action, after the full-bit hashes are in.

## Context

The remediation write path is fully implemented and tested — the orchestrator signs an `ActionJob`,
the agent's `SignedJobListener` verifies it (signature + nonce + expiry + host scope) and the
`ActorDispatcher`/`Executor` perform the guarded, TOCTOU-safe mutation — but **only in-process**.
Every test wires core's dispatch callables straight to an in-process listener (`_wire_runtime`).
In a real deployment there is no channel between core (on the core host, nas-1) and a remote agent
(on a fleet node, or even nas-1's own scanner container):

- nothing sets `app.state.remediation_runtime`, so `get_runtime()` returns `503` (default-OFF);
- the agent (`python -m fathom.agent`) runs **one scan→stage→push pass and exits** — it never
  listens for jobs;
- there is no core job-dispatch surface, no orchestrator signing-key provisioning, and no agent
  `write_enabled` + pinned orchestrator key in production.

So "enable Apply" is not a config flip — it requires building the channel that actually carries
delete/move jobs to the host. This is the single most security-sensitive subsystem in Fathom, so it
gets its own ADR and an adversarial review, and it is **built default-OFF** so it can land, deploy,
and sit inert until deliberately enabled per host (after the full-bit hashes are in).

The standing owner ruling (already documented in `remediation_runtime.py` and `listener.py`):
**dispatch is agent-initiated outbound** — the agent long-polls core for signed jobs; core never
opens a connection to the agent. This keeps the agent with **no inbound port** (the same boundary as
mTLS ingest), so enabling remediation adds no new attack surface on the fleet hosts.

## Decision

### 1. Core job-dispatch surface (on the mTLS agent boundary, fingerprint-auth like ingest)
Two routes, mounted on the existing agent ingest boundary (mTLS + `X-Client-Cert-Fingerprint`, NOT
human SSO), each scoped to the calling host's fingerprint so a host can only ever see its own jobs:

- `POST /api/v1/agents/jobs/poll` — long-poll: the agent presents its cert; core returns the next
  pending `SignedJob` for that host id, or `204` after a bounded long-poll timeout (the agent
  re-polls). A host that polls can only receive jobs whose `host_id` maps to its fingerprint.
- `POST /api/v1/agents/jobs/{job_id}/result` — the agent posts back the `JobResult` (drift report
  for DRY_RUN, exec results for EXECUTE). Core correlates by `job_id`/nonce and resolves the
  awaiting dispatch call.

A **job queue + result correlation** (a small in-DB table `action_job` already exists for the
single-use ledger; extend it with a `pending`/`claimed`/`done` lifecycle + the serialized signed
job + the returned result, OR an in-memory per-host queue with a DB-backed nonce ledger for
single-use). The orchestrator's `DryRunDispatch`/`ExecuteDispatch` callables become: enqueue the
signed job for `host_id`, then await the correlated result (with a timeout) — replacing the
in-process loopback. The `Executor.execute_with_audit` path (the per-item act audit, currently the
deferred security-review TODO) is wired through the result channel here so the destructive act lands
on the durable hash-chained store end-to-end.

### 2. Agent daemon (listen) mode
A new agent mode (`python -m fathom.agent listen`, or `FATHOM_AGENT_MODE=listen`) that, instead of a
one-shot scan, runs a loop: **long-poll core → verify (`SignedJobListener`) → execute
(`ActorDispatcher`) → post results**. It refuses to start unless `write_enabled` AND
`orchestrator_pubkey_ref` AND `quarantine_dir` are all configured (fail-closed). Scanning and
listening are separate invocations/containers, so a scan-only host never carries the write path.

### 3. Runtime provisioning at core startup
Build the `RemediationRuntime` (signer + the queue-backed dispatch callables) from an Ed25519
signing key loaded **by reference** from the secret backend (ADR-010), and set it on
`app.state.remediation_runtime` — **only when** `remediation_enabled` is true AND a signing key is
provisioned. Absent either, the runtime stays unset → `get_runtime()` 503s (the existing default-OFF
behaviour is preserved; there is no silent no-op).

### 4. Key management
Generate an orchestrator Ed25519 keypair; the **private** key lives only in core's secret backend
(by-reference, never in `.env`/image). The **public** key (and its `key_id`) is distributed to the
agent as `orchestrator_pubkey_ref`, which the listener pins — rejecting any job under a different
`key_id`. Rotation is a new `key_id` + redistribution.

### 5. Default-OFF, staged per-host enablement
Deploying all of the above changes nothing until, per host: (a) server `remediation_enabled=true`,
(b) a signing key provisioned (runtime built), (c) the agent runs in listen mode with
`write_enabled` + the pinned pubkey + a quarantine dir. So it is built, tested, deployed, and left
inert; nas-1 is enabled first as a pilot once the full-bit hashes are in.

## Consequences

### Positive
- Completes the write path that the orchestrator/listener/executor were always designed for, over
  the agent-initiated outbound channel — **no new inbound port** on any fleet host.
- Every existing guard still wraps it: signed single-use nonce + expiry + host scope, dry-run-first,
  blast cap, fresh step-up MFA, the danger-zone host-confirm + risk audit (ADR-025-adjacent commit),
  audit-before-act. Default-OFF on three independent gates → safe to ship disabled.
- Closes the deferred "per-item act audit onto the durable chain" TODO by widening the result
  channel to carry the executor's audit records.

### Negative
- A new always-on agent **listener process** (vs. the one-shot scanner) and a **job queue + result
  correlation** layer — more moving parts and a long-poll connection to maintain.
- Key provisioning + distribution is operational work (generate, store by-reference, pin on agents).

### Risks
- **Queue / correlation bugs** (a job delivered twice, to the wrong host, or a result mis-correlated)
  → mitigated by per-fingerprint job scoping, the single-use nonce ledger (`used_nonce`), and the
  signed `host_id` the listener re-checks; covered by an adversarial test set (cross-host job
  leakage, replay, expiry, tampered job, result spoofing).
- **Key compromise / distribution** → private key by-reference only, `key_id` pinning + rotation,
  and the act is still drift-gated + MFA-gated + audited.
- **Build risk on the most dangerous code** → built default-OFF, behind its own ADR + a dedicated
  adversarial review before any host is enabled (never rushed at the tail of unrelated work).

## Build order (so it can land disabled, then enable later)
1. Job queue + correlation + the two dispatch routes (core), default-OFF; unit + adversarial tests.
2. Wire `DryRunDispatch`/`ExecuteDispatch` to the queue; thread the per-item act audit back.
3. Runtime provisioning at startup (signer from secret backend; absent → 503).
4. Agent `listen` mode (loop over `SignedJobListener`/`ActorDispatcher`); fail-closed without
   write_enabled + pinned key + quarantine dir.
5. Key generation + distribution tooling.
6. Adversarial review of the whole channel; fix all findings.
7. **Only then**, and after the full-bit hashes are in: provision the key + enable on **nas-1
   first**, behind the danger-zone gate, and watch one real (reversible, quarantine) action through
   end-to-end before any wider rollout.

## As-built summary (steps 1–6, default-OFF)

**Job host scope = the business host id (`Host.name`).** The signed `job.host_id`, the per-host
queue key, and the agent's pinned `host_id` are all the business host id (== the agent's configured
`host_id` == `Host.name`), *not* the DB surrogate. This is what lets the agent's listener
**independently** re-verify scope (the defence-in-depth check only has value if the agent knows its
identity without trusting core's routing). RBAC scope + `Host` lookups still use the DB id.

**Queue (option B): in-memory per-host queue + DB nonce ledger; single-worker.**
`fathom.core.remediation.job_queue.JobQueue` holds an `asyncio.Queue` per host id (claim-once) and
an `asyncio.Future` per `job_id` (resolve-once). `enqueue_and_wait` blocks the orchestrator's
dispatch on the correlated result, bounded by the job TTL (so a timed-out dispatch == an expired
job the agent refuses — no act-after-give-up). Correlation state is always reaped in a `finally`.
**Core must run a single worker** (the deployed `uvicorn` has no `--workers`); the awaiting-handler
model is inherently in-process. Durable single-use is the `used_nonce` ledger, consumed in the
result route (a replayed result is rejected across a restart).

**Routes** (`fathom.api.routers.agent_jobs`, on the mTLS `FingerprintDep` boundary, NOT human SSO):
`POST /api/v1/agents/jobs/poll` (long-poll, host resolved from the cert fingerprint, returns the
next signed job or 204) and `POST /api/v1/agents/jobs/{job_id}/result` (ownership-checked, nonce
consumed, future resolved). The poll resolves the host in a *transient* session and then holds **no**
DB connection during the long wait (pool-exhaustion guard).

**Audit threading (closes the deferred fix (2)).** The EXECUTE dispatch contract widened to
`ExecuteOutcome(results, audit)`; the agent returns the executor's per-item act audit over the
result channel and the orchestrator splices it onto the durable hash-chained store
(`AuditChain.splice`), so the destructive act itself lands on the tamper-evident log. The agent
*also* appends a durable local act-audit JSONL (so a lost result still leaves a host-side record).

**Provisioning (`build_remediation_runtime`).** At startup the runtime is built **only when**
`remediation_enabled` AND a signing key resolves by reference (ADR-010); absent either → unset →
`get_runtime` 503s. A key reference that is set-but-invalid raises and aborts startup (fail loud,
never half-armed).

**Agent `listen` mode** (`python -m fathom.agent listen`): fail-closed startup (refuses without
`write_enabled` + `orchestrator_pubkey_ref` + `quarantine_dir`); pins the orchestrator key by the
configured algorithm (`orchestrator_signing_algorithm`, default Ed25519 — no auto-detection); loops
poll→verify→execute→post, surviving a core bounce.

**Key tooling.** `python -m fathom.admin remediation-keygen <out_dir>` generates the Ed25519
keypair (private 0600 → core's secret backend by reference; public + `key_id` → agents); logs paths
+ guidance only, never key material.

**Adversarial review (two lenses) — findings fixed:** poll held a DB connection during the 25s
long-poll (→ transient session); unbounded result payload (→ list/field caps reject a flood as 422);
no durable agent-side audit on a lost result (→ local JSONL); silent algorithm auto-detection on the
agent (→ explicit algorithm pinning, fail loud); HMAC fallback had no minimum secret length
(→ ≥32 bytes); local audit moved inside the actor-owned quarantine dir. The reviews confirmed no
cross-host leakage, ADR-010 secret-by-reference compliance, and that the queue's critical sections
are atomic under the single-worker model.

**Default-OFF, three independent gates, all off as shipped:** server `remediation_enabled`, a
provisioned signing key (runtime built), and the agent's `write_enabled` + pinned key. Deployed
inert; step 7 (per-host enablement) remains the operator's separately-authorised action.
