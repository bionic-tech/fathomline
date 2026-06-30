# ADR-036 — Scan concurrency coordinator (defer overlapping heavy scans)

**Status:** Accepted  **Date:** 2026-06-19  **Deciders:** project owner

## Context

Scans are triggered by independent per-host timers (systemd / TrueNAS cron). When several **heavy**
scans land on the core at once, their reconcile/finalize queries saturate the single core Postgres
and ingest pushes start failing — observed live when three hosts' big scans overlapped (one host's
full drain runs ~2 h, and two others' timers fired into that window). The agents are one-shot,
push-only, with no inbound port, so the core cannot "pause" a running agent; coordination must be a
decision the agent *asks for* before it starts. The notifications subsystem (ADR-031) is designed
but **not built**, so the "tell me why / when" advisory needs another home.

## Decision

A core-side **scan lease** the agent requests just before walking — the model is *propose/grant or
defer*, never a hard lock the core imposes:

- **`POST /api/v1/agents/scan-lease`** (agent-facing, same mTLS boundary as ingest; host = verified
  cert fingerprint). The core returns **GRANT** (run now) or **DEFER** (skip this run). The agent
  honours a defer by exiting cleanly — the next scheduled run retries — and is **fail-open**: any
  error / missing endpoint / disabled coordinator proceeds with the scan, so coordination can never
  *block* scanning, only *order* it.
- **Heaviness** is derived, not configured per host: a scan is heavy when the host's last
  :class:`AgentRun` saw ≥ `scan_coordinator_heavy_entries` entries (the dominant driver of the
  core's reconcile cost); a host with no prior run is treated as heavy (conservative). **Light scans
  are always granted** — they don't overload the core.
- **Policy:** a heavy scan is granted only if fewer than `scan_coordinator_max_concurrent_heavy`
  (default **1** — strict serialization) heavy leases are active; otherwise it is deferred.
- **Lease lifecycle:** a grant inserts an `active` row with a TTL; the lease is **released when the
  agent reports its run** (`/agents/runs` — the natural "scan done" signal, no extra agent call),
  and the TTL (`scan_coordinator_lease_ttl_seconds`, default 6 h) auto-expires a crashed agent's
  lease so the fleet never wedges. A re-request supersedes the host's own prior lease.
- **Advisory (why + when):** a defer writes a `scan_lease` row (`status=deferred`) carrying the
  reason, the blocking host, and the advised `retry_after_seconds`. That row doubles as the
  operator-facing advisory, read at **`GET /api/v1/scan-coordinator/advisories`** (`VIEW_METADATA` +
  scope). When ADR-031 ships, the same event can also be emitted as a notification.

State lives in one portable `scan_lease` table (migration `d5e6f7a8b9c0`); the decision logic is in
`fathom.core.scan_coordinator`.

## Consequences

- **Default-OFF** behind `scan_coordinator_enabled`: the endpoint **grants unconditionally** when
  off, so the agent can always ask and the feature is inert until an operator enables it — no
  flag-day, deploy-then-enable. It changes only **when** a scan runs, never **what** it sees
  (read-only w.r.t. the catalogue).
- Solves the observed failure: with `max_concurrent_heavy=1`, the fleet's big scans run one at a
  time instead of piling onto the core — complementing (not replacing) the Postgres `shm_size`
  bump, which fixed the *symptom* (shared-memory exhaustion) while this removes the *cause*
  (concurrent heavy reconciles).
- Agent change is minimal + fail-open (a pre-walk lease check in `__main__`), shipped in the image;
  enabling is a core-only setting.
- Not built here (future): emitting the advisory through ADR-031 notifications; a smarter "advised
  window" (e.g. the blocking host's typical finish time) instead of a fixed retry-after; a small
  retention prune of old `scan_lease` rows.
