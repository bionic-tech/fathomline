# ADR-031: Notifications — threshold alerts + scheduled digests

**Status:** Proposed **Date:** 2026-06-11 **Deciders:** project owner

## Context

Fathomline (engine codename "fathom") gives an operator a rich read surface over their estate:
volumes with capacity (`Volume.total/used/free`, `src/fathom/core/catalogue/models.py:74-76`,
projected as `VolumeOut`, `src/fathom/api/schemas.py:146`), growth-over-time
(`SizeHistory`, `src/fathom/core/catalogue/models.py:225`; `growth_series`,
`src/fathom/core/query_charts.py:262`), report-only duplicate groups
(`DupGroup.reclaimable_bytes`, `src/fathom/core/catalogue/models.py:269-285`; surfaced as
`DuplicatesSummaryOut`, `src/fathom/api/schemas.py:313`), the per-path churn feed
(`ChangeLog`, `src/fathom/core/catalogue/models.py:239`), and fleet scan-health
(`AgentRun.outcome` ∈ `ok|partial|failed`, `src/fathom/core/catalogue/models.py:103-133`;
`latest_run_by_host`, `src/fathom/core/agent_runs.py:77`).

All of that is **pull**: a human has to open the UI or poll the API to learn that `tank` on
`nas-1` crossed 95 % full, that a scan went `partial` overnight, or that a new full-bit pass
surfaced 400 GiB of reclaimable duplicates. The product targets four delivery modes:

1. **In-UI** — already shipped (the dashboard/charts/Agents tab).
2. **API** — already shipped (the read routers).
3. **Event-driven threshold alerts** — *the gap*: nobody is told when a metric crosses a line.
4. **Scheduled digests** — *the gap*: no periodic "state of the estate" summary lands in an inbox.

This ADR designs modes 3 and 4. The audience is primarily self-hosted homelab / OSS operators
who want a webhook into their existing stack (ntfy, Gotify, Discord, Matrix, Slack, a Home
Assistant automation) and/or plain email, but the same subsystem must serve SSO orgs with
per-host/volume-scoped recipients (one person owns `nas-1`, another owns `node-1`).

**Safety stance (non-negotiable):** Notifications are **read-only**. They observe the
catalogue and push summaries/alerts outbound; they **never** trigger remediation and **never**
write to the estate. This mirrors the report-only boundary the Duplicates surface already draws
(`DupGroup` is "report only … the report commits no filesystem change",
`src/fathom/core/catalogue/models.py:269-277`) and keeps the destructive write path firmly
behind the remediation gates (`remediation_enabled`, `src/fathom/core/settings.py:75`), which
this subsystem does not touch.

## Decision

Introduce a **Notifications** subsystem with two halves — an **event/threshold model** that
decides *what is worth telling someone* and a **pluggable `Channel` protocol** that decides
*how it is delivered* — mirroring the pluggable-provider pattern Fathom already uses for
`InferenceProvider` (ADR-022), `StorageBackend` (ADR-004), `PlatformAdapter` (ADR-008), and the
secret backend (ADR-010). The whole subsystem is **default-OFF** behind a feature flag, exactly
like remediation/preview/organize (`src/fathom/core/settings.py:75,95,173`).

### 1. The `Channel` protocol (pluggable delivery seam)

A structural-typing protocol (like `InferenceProvider`, ADR-022) with one job: take a rendered,
already-scope-filtered `NotificationMessage` and attempt delivery, returning a typed
`DeliveryResult` (delivered / transient-failure / permanent-failure). It knows nothing about
thresholds, the catalogue, or scopes — a thin, reusable delivery seam.

- **`WebhookChannel`** (P1 default) — POSTs a JSON payload to an operator-supplied URL. The
  homelab lingua franca (ntfy/Gotify/Discord/Matrix/HA all speak inbound webhooks).
- **`SmtpChannel`** (P2) — email via SMTP; the natural home for digests.
- **`AppriseChannel`** (P3) — wraps [Apprise](https://github.com/caronc/apprise) as a
  multiplexer so an operator gets 90+ targets (Telegram, Pushover, Slack, …) from one
  config string, without Fathom growing a transport per service. Noted as the homelab-friendly
  fan-out option, kept opt-in so it stays an optional dependency.

Channel selection + config is `FATHOM_*` settings (`src/fathom/core/settings.py:17`,
`env_prefix="FATHOM_"`). All channel credentials are **secret references**, never inline
(see Security).

### 2. The event/threshold model

A `Subscription` binds *what to watch* (one or more event types, each with a threshold) to a
*scope* (§3) and a *channel*. Evaluation produces an `Event`; an `Event` that passes
rate-limit/dedup (§4) renders into a `NotificationMessage` and is handed to the channel.

Event sources, each read **only** from the existing read surfaces (no new scan, no agent
round-trip):

| Event | Source | Threshold |
|---|---|---|
| **low-free-space** | `Volume.free / Volume.total` per volume (`models.py:74-76`) | `free_pct < X` (per-volume %) |
| **growth-spike** | `SizeHistory` delta over a window (`models.py:225`; `growth_series`, `query_charts.py:262`) | `delta_bytes > X` over `window` |
| **dup-delta** | new/changed `DupGroup` reclaimable bytes (`models.py:269-285`) | `reclaimable_bytes > X` |
| **scan-failure** | `AgentRun.outcome` ∈ {`partial`,`failed`} (`models.py:103-133`; `agent_runs.py:22-24`) | any non-`ok` outcome |

The server is the **only** authority for the metric (it never trusts an agent-asserted
aggregate — the same posture `record_agent_run` takes when it re-derives `outcome` rather than
trusting the body, `src/fathom/core/agent_runs.py:36-71`).

### 3. Evaluation rides the existing worker, not ingest

Threshold evaluation and digest rendering run **after** ingest + rollup finalize, on the
existing background-worker pattern — **never inline** on the ingest path. The natural hook is
the post-drain finalize the agent already calls: `FinalizeService.finalize_host`
(`src/fathom/core/finalize.py:71`), invoked by `POST /api/v1/agents/finalize`
(`src/fathom/api/routers/ingest.py:37-59`). That is exactly where the report-only dedup rebuild
already rides ("the post-drain finalize the agent already makes is exactly that post-ingest
hook", `src/fathom/core/finalize.py:14-16`) — notification evaluation joins it as a *follow-on*
task, not as part of the finalize transaction, so a slow or failing channel can never stall a
drain.

Two task shapes, both modelled on the existing workers in `src/fathom/workers/`:

- A **threshold-evaluation task** dispatched after finalize — same transport-agnostic shape as
  `run_dedup` / `dedup_task` (`src/fathom/workers/dedup.py:27,45`): a coroutine that owns its
  own DB session, runnable inline-as-interim or on an arq/Valkey queue later. The `__init__`
  already names a planned `notify` worker (`src/fathom/workers/__init__.py:1`).
- A **digest scheduler** — a cancellable stdlib-asyncio periodic loop, copied from
  `RetentionWorker` (`src/fathom/workers/retention.py:41-91`): per-recipient daily/weekly
  summary, one failed tick logged-and-swallowed so the loop survives (`retention.py:86-90`).

This keeps the broker optional (owner ruling embedded in `retention.py:5-12`: "a stdlib asyncio
queue if adding Redis is heavy — keep it testable and gate-green").

### 4. RBAC scoping — deny-by-default, reuse `ScopeFilter`

A `Subscription`/recipient is bound to a **scope** (global / host-set / volume-set) and only
ever receives alerts and digest content for volumes that scope covers — identical to the read
API, reusing `ScopeFilter` (`src/fathom/auth/scope.py:44`) rather than inventing a parallel
mechanism:

- The scope is **server-authoritative**, built from the assignment store via
  `ScopeFilter.from_grants` (`scope.py:56`), never from client input (`scope.py:11-14`).
- Every metric query that feeds a subscription is filtered with `ScopeFilter.apply`
  (`scope.py:93`), pushing the in-scope `host_id`/`volume_id` predicates into the query, so an
  out-of-scope volume can never appear in an alert body or a digest.
- **Deny-by-default / fail-closed**: an empty non-global scope returns nothing
  (`ScopeFilter.is_empty` → deny-all, `scope.py:75-78`; `apply` adds `where(false())`,
  `scope.py:121-123`). A subscription whose grant was revoked silently stops delivering rather
  than leaking.
- The **system-volume gate** (AR-011) is honoured: a digest/alert names a `kind == 'system'`
  volume only when a volume-scoped grant names it explicitly (`scope.py:80-91,126-133`), so a
  host-scoped recipient never even learns a root/system volume's free space.

A capability — `RECEIVE_NOTIFICATIONS` — gates *who may own a subscription*, resolved through the
same grant→capability machinery (`role_has`, `scope.py:59`).

### 5. Security

- **SSRF on operator-supplied webhook URLs.** A webhook URL is attacker-influenced input. The
  `WebhookChannel` must, before connecting: enforce an `https`(/`http` only in dev) scheme;
  resolve the host and **refuse private/link-local/loopback/metadata ranges** (RFC1918,
  `127.0.0.0/8`, `::1`, `169.254.169.254`, `fd00::/8`) unless an explicit operator allowlist
  permits an internal target; re-validate the resolved IP at connect time to defeat
  DNS-rebinding; disable redirects to a fresh host. This is the same "validate at the boundary,
  fail closed" stance the codebase already takes with the path-traversal containment and the
  ingest-proxy-secret (`src/fathom/core/settings.py:30-32`). No internal-metadata endpoint is
  ever reachable via a notification target.
- **SMTP / webhook-auth credentials are secret references (ADR-010).** SMTP password, webhook
  bearer token, and any auth header are stored as a **reference into the secret backend**, never
  inline — exactly like `remediation_signing_key_ref` (`src/fathom/core/settings.py:84-86`),
  `inference_openai_key_ref` (`settings.py:190`), and `preview_cache_key_ref` (`settings.py:128`).
  Resolution uses the existing `SecretProvider = Callable[[str], str]` seam
  (`src/fathom/api/remediation_runtime.py:47-49`). Credentials are never logged; redacted-repr
  discipline follows `SshCredential` (`src/fathom/core/deploy/credentials.py:35-43`).
- **No estate leakage beyond scope.** Alert/digest bodies carry only what the recipient's
  `ScopeFilter` already authorises — same predicate as the read API (§4). Paths from
  `change_log`/`dup_member` are included only for in-scope volumes; nothing carries a secret or a
  full-bit hash that the read surface itself would not show.
- **Rate-limiting / dedup so a flapping threshold can't spam.** A volume hovering at the
  free-space line must not fire on every finalize. Each `(subscription, event-key)` carries a
  cooldown + last-fired timestamp; an event re-fires only after the cooldown or after it clears
  and re-crosses (hysteresis). This is the alerting analogue of the `used_nonce` single-use
  ledger (`src/fathom/core/remediation/models.py:122-131`).
- **Delivery audit trail.** Every delivery attempt (subscription, channel, event-key, outcome,
  retry count) is appended to a `notification_delivery` audit table so an operator can answer
  "was I told, and did it land?". It reuses the append-only audit discipline of
  `RemediationAuditRow` (`src/fathom/core/remediation/models.py:134-159`) — append-only, never
  updated in place. The hash-chain rigour of the remediation audit is *not* required here
  (delivery is non-destructive), but the append-only + auditable shape is, and the durable-append
  helpers in `src/fathom/core/audit_store.py` are the reference implementation.

### 6. Failure modes

- **Channel down → retry with backoff.** A `transient-failure` `DeliveryResult` is retried with
  bounded exponential backoff and a max-attempt cap; a `permanent-failure` (4xx, bad config) is
  recorded and not retried. The retry loop is bounded like the audit fork-retry
  (`_MAX_APPEND_RETRIES`, `src/fathom/core/audit_store.py:54-55`) so a dead endpoint can never
  spin forever.
- **A delivery failure never affects a scan or ingest.** Evaluation/delivery runs as a follow-on
  task off the finalize hook (§3), in its **own** transaction, exactly as the dedup worker does
  (`src/fathom/workers/dedup.py:37`). A raised exception is logged-and-swallowed per the
  `RetentionWorker` loop discipline (`src/fathom/workers/retention.py:86-90`); ingest and rollup
  finalize commit regardless of whether anyone could be notified.
- **Idempotent digests.** A digest is keyed by `(subscription, period)` so a worker restart or a
  double-tick re-sends nothing already delivered for that period — the same idempotency-key
  discipline used for remediation plan building
  (`RemediationPlanRow.idempotency_key`, `src/fathom/core/remediation/models.py:67`). The
  scheduler "catch-up after a missed tick" behaviour follows the retention worker's note that a
  missed tick is harmless (`src/fathom/workers/retention.py:25-27`).

## Consequences

### Positive
- Closes the only two un-served delivery modes (event alerts + digests) with one seam each — a
  `Channel` protocol and an event/threshold model — instead of bolting per-service code onto the
  read path.
- Read-only by construction: it reuses the existing read queries + `ScopeFilter`, so it cannot
  leak out-of-scope data and cannot touch the estate. The destructive boundary is untouched.
- Homelab-first (a webhook is enough) while serving SSO orgs (per-host/volume recipients) from
  the same RBAC the read API already enforces.
- Default-OFF and broker-optional: ships gate-green without provisioning Valkey, like dedup and
  retention.

### Negative
- A new (small) data model — `Subscription`, dedup/cooldown state, `notification_delivery` audit
  — plus migrations, to maintain.
- SSRF allowlisting and DNS-rebind defence are fiddly to get right and must be tested
  adversarially; a permissive webhook validator is a real internal-scanning vector.
- Three channels + Apprise's optional dependency to document and test; SMTP deliverability
  (SPF/DKIM) is the operator's problem and a likely support burden.

### Risks
- **Alert spam** from a flapping threshold → mitigated by per-event cooldown + hysteresis (§5).
- **SSRF / internal pivot** via a malicious webhook URL → mitigated by scheme + IP-range
  validation, connect-time re-resolution, no cross-host redirects (§5).
- **Scope drift** (a recipient keeps getting alerts after a grant is revoked) → mitigated by
  resolving `ScopeFilter` from the live grant store at evaluation time, fail-closed (§4).
- **Secret leakage** → channel credentials are by-reference (ADR-010), never logged, never in a
  message body (§5).

### Phased plan
- **P1** — `WebhookChannel`; **low-free-space** + **scan-failure** alerts; per-event
  cooldown/dedup; delivery audit; evaluation on the finalize follow-on task. The highest-signal,
  lowest-data-leak events over the homelab-default transport.
- **P2** — scheduled **digests** + `SmtpChannel`; idempotent per-period digest; the digest
  scheduler loop.
- **P3** — **growth-spike** + **dup-delta** alerts; `AppriseChannel` multiplexer.

### Out of scope (explicitly)
- **No write actions.** Notifications never remediate, never quarantine, never delete, never
  enqueue a job — they observe and push only.
- **No per-file alerting.** Events are estate/volume/group/scan-grained (a noisy per-`fs_entry`
  or per-`change_log`-row alert is a deliberate non-goal); the churn/per-file detail stays a
  pull-only read surface.
- **No inbound/interactive channels** (no reply-to-act, no bot commands) — that would breach the
  read-only stance.
