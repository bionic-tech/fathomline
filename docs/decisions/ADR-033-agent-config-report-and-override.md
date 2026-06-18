# ADR-033 — Agent self-reported config + operator config override (pull, fail-safe)

**Status:** Accepted  **Date:** 2026-06-15  **Deciders:** project owner

## Context

An operator looking at the **Agents** page can see fleet health (last run, version, volume count)
but **not what each agent is actually configured to do** — its `scan_scope`, `fullbit_scope`,
`cross_mounts`, `write_enabled`, and `throttle`. That config lives only in each host's local
`agent.config.yaml` (loaded from `FATHOM_AGENT_CONFIG`), so the only way to know a host's scan scope
today is to SSH in and read the file (we keep a hand-maintained copy in `deploy/FLEET-VOLUMES.md`).
Two needs follow: **(#9)** see the effective config in the UI, and **(#10)** change it from the UI
without per-host SSH + container recreate.

Constraints that shape the design:
- **Agents are scheduled, one-shot scanners** (`restart: "no"`), not always-on daemons — only the
  listen/preview-serve daemons poll continuously. So a *push* channel (core → agent inbound) is the
  wrong shape; the agent must **pull**.
- **The agent-initiated mTLS channel already exists** (the agent authenticates to the core with its
  client cert; the proxy stamps `X-Client-Cert-Fingerprint`, resolved to a `Host` by
  `require_client_fingerprint` / `record_agent_run`). Reuse it — **no new agent inbound port, no new
  signing scheme** (mirrors the owner ruling for preview/dispatch).
- **Config drives what gets read on a live fleet.** A bad override (e.g. an out-of-scope path, a
  `write_enabled` flip, a fullbit scope that hammers a degraded pool) must never silently break or
  endanger a host — so the agent, not the core, is the final authority on its own config.

## Decision

**Agent reports its effective config; the core may hold a desired override the agent pulls and
validates at run start, fail-safe to the local file.**

1. **Report (#9).** At the end of each run the agent includes its **effective config** (the same
   `AgentConfig` it ran with, secret-path fields elided) in the existing `AgentRunReport` it POSTs to
   `/api/v1/agents/runs`. The core stores it on `host.reported_config` (JSON, latest-wins) and the
   `agent_run` row (per-run audit). `HostOut.reported_config` exposes it; the Agents UI shows it in a
   per-host expander. Read path is `VIEW_METADATA`, scope-filtered like the rest of `/agents`.

2. **Override (#10).** An operator with **`MANAGE_AGENTS`** sets a per-host **override** via
   `PUT /api/v1/agents/{host_id}/config` — a *partial* config of only the safe, operator-tunable
   fields: `scan_scope`, `fullbit_scope`, `cross_mounts`, `throttle`. It is stored on
   `host.desired_config` (JSON) and **audited** (who/when/what). It is **not** applied by the core.
   **`write_enabled` is deliberately NOT overridable** — enabling the agent's write/quarantine path
   is security-sensitive and stays in the host's local file (it is *shown* read-only in the view).

3. **Pull + apply (#10), fail-safe.** At **run start** (before the scan loop) the agent does one
   `GET /api/v1/agents/config` (agent-facing, fingerprint-auth). If the core returns an override, the
   agent **merges it over its local `AgentConfig` and re-validates the whole result with the same
   Pydantic model** (`extra="forbid"`, the existing scope/subset/path validators). On ANY failure —
   network error, `404`/`204`, or a merged config that fails validation — the agent **logs and keeps
   its local config** and proceeds. Identity + transport fields (`host_id`, `ingest_url`, cert paths)
   are **never** overridable. The agent reports the *effective* (post-merge) config in step 1, so the
   UI always shows what actually ran.

The override is **opt-in and empty by default**: with no `desired_config` set, the agent runs its
local file unchanged — so shipping the mechanism does not alter the current fleet's behaviour.

## Consequences

- **Positive:** the Agents page answers "what is each host configured to scan, and how throttled?"
  (#9) and lets an operator retune scope/throttle fleet-wide from one place (#10) — the override
  takes effect on the host's next run, no SSH. The agent stays the authority on its own config, so a
  bad override degrades to "ran with the previous good config" rather than a broken/over-reaching
  scan. Reuses the existing mTLS channel + Pydantic validation; no new inbound surface.
- **Negative / risks:** an override only takes effect on the next run (one-shot cadence) — not
  instant. The reported config widens what the core stores about a host (mitigated: secret *paths*
  are elided, never secret values). A careless override could narrow scope or over-throttle — mitigated
  by `MANAGE_AGENTS` gating, the audit record, agent-side re-validation, the non-overridable
  identity/transport fields, and keeping `write_enabled` out of the override set. Populating the view
  requires agents on the **new image**
  (older agents simply report nothing → UI shows "not reported yet").
- **Migration:** add `host.reported_config` + `host.desired_config` (JSON, nullable) and
  `agent_run.reported_config` (JSON, nullable). All default null → behaviour-preserving.

## Cross-references

ADR-015 (`(host,volume,dev,inode)` identity), ADR-017 (defence-in-depth ingest auth — the same
fingerprint dependency authorises the config GET), ADR-025 (agent-initiated signed-job channel — the
*push* analogue this deliberately does NOT copy, because config is pull-on-run not event-driven),
ADR-026 (agent deployment — the heavier "stand up / re-image an agent" surface; this ADR is the
lightweight in-place config retune), `deploy/FLEET-VOLUMES.md` (the hand-maintained scope record this
replaces in the UI).
