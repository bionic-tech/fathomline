# ADR-034 — Scan-scope builder: live volume picker + directory explorer + subtree excludes

**Status:** Accepted  **Date:** 2026-06-15  **Deciders:** project owner

## Context

Scan scope is entered as **free-text absolute paths** — in the Deploy wizard (new host) and in the
Agents config override (ADR-033 #10). The operator must already know the host's exact mountpoints
and directory layout, can't discover what's there, and typos silently produce "not within
scan_scope" skips. Two concrete asks from the e2e review:

1. A **df-style dropdown of the host's mounted volumes** (like the *Mounted on* column of `df -TH`)
   to pick a scan root, instead of typing it.
2. An **Explore** button → **directory tree** to navigate and select a folder — *including folders
   that have not been scanned yet* — plus the ability to **include a subtree but exclude specific
   sub-directories** (e.g. include `C:\` but exclude `C:\Windows`; include `/home/*` but not `/`).

Constraints that shape the design:
- **Enrolled agents are mTLS-push-only, one-shot scanners** (ADR-033 context) — no inbound port. So
  "browse the live host filesystem" cannot be a direct call to the agent; it must ride the existing
  **agent-initiated** channel. The **ADR-025 signed-job dispatch channel** is exactly that pull
  channel (built, default-OFF/inert today).
- **Deploy targets are not enrolled yet**, but the push-mode wizard holds an **SSH connection** to
  the host (ADR-026) — it can probe `df` and list directories live over that connection.
- **The catalogue already holds df-equivalent data** for enrolled hosts: the `volume` table
  (mountpoint, fs_type, total/used/free) and the scanned `/tree`. That's the fast, already-gated
  source — but it only knows **scanned** paths, so it cannot satisfy "pick a folder I haven't
  scanned yet" on its own.
- **Listing a host's real filesystem is sensitive** — it reveals directory structure and could be
  pointed at secret-bearing paths. It must be read-only (names/types/sizes, never content),
  bounded, path-safe (no symlink escape / traversal), `MANAGE_AGENTS`, scope-checked, MFA step-up
  gated, and audited.

## Decision

Build a **scope builder** shared by the Deploy wizard and the Agents override, with three parts.
The tree explorer is **phased**: the fast catalogue source needs no new agent capability; reaching
un-scanned directories is a gated, read-only live-browse.

1. **Volume picker (df-style dropdown).**
   - *Agents page:* from the catalogue — `GET /api/v1/volumes` filtered to the host (mountpoint +
     fs_type + total/used/free). This *is* the agent's last-seen `df`, so no live call is needed.
   - *Deploy wizard:* a live `df -TH`-equivalent probe over the enrollment SSH connection (a
     preflight sub-step), since a new host has no catalogue yet.
   Selecting a volume adds its mountpoint to the include list (and is the explorer's starting root).

2. **Directory explorer (tree).** Navigate directories under the chosen volume; add a node to the
   **include** or **exclude** list.
   - *Fast / default — catalogue:* `GET /api/v1/tree` (scanned dirs, `is_dir`). Instant, read-only,
     already `VIEW_METADATA`-gated. Covers refining scope among already-scanned paths.
   - *Live — un-scanned dirs (gated, Phase 2):*
     - *Agents:* a new **read-only `list_dir` job** over the ADR-025 dispatch channel. The operator
       requests a host+path listing; the core enqueues a **signed** `list_dir` job; the agent's
       listen daemon pulls it, lists **one** directory (entry name, `is_dir`, size, mtime — **no
       content, no recursion**), and returns the result, which the UI renders. `list_dir` is
       **independent of `write_enabled`** (it is a read, not a remediation) but requires the dispatch
       channel enabled.
     - *Deploy:* the same bounded, read-only listing over the SSH connection.
   - The explorer shows catalogue data immediately and offers a **"browse live"** affordance (gated)
     that fills in un-scanned entries.

3. **Subtree excludes.** A new **optional, operator-overridable** config field
   **`exclude_scope: list[str]`** — absolute directory prefixes. The agent walker **prunes** any path
   at or under an excluded prefix (it never descends into it). Re-validated exactly like `scan_scope`
   (absolute, path-safe); included in `AgentConfig.reportable()` and in the `AgentConfigOverrideIn`
   (#10) and Deploy initial config. **Subtree semantics only** (matches the stated needs); glob
   patterns (`**/node_modules`) are explicitly deferred.

4. **Security / gating.** Live browse (dispatch `list_dir` *and* SSH listing) requires
   `MANAGE_AGENTS` **plus a fresh MFA step-up** (`FATHOM_MFA_FRESHNESS_SECONDS`), is **scope-checked**
   to the target host, and is **audited** (`build_persistent_chain`). Listings are read-only, one
   level deep, entry-count capped, and reuse the scanner's path-safety (no symlink escape, no `..`).
   No file bytes ever cross the channel. The catalogue tree/volume sources keep their existing
   `VIEW_METADATA` gate (the data is already in the DB).

## Consequences

- **Phase 1 (no new agent capability, ship first):** `exclude_scope` in `AgentConfig` + the walker
  prune + `reportable()` + `AgentConfigOverrideIn`; the volume dropdown (catalogue) + catalogue
  `/tree` explorer + include/exclude list builder on the Agents override; manual path entry stays for
  un-scanned paths. `exclude_scope` ships in the override immediately and needs an agent redeploy for
  the walker change.
- **Phase 2 (gated live-browse):** the `list_dir` dispatch job (agents) and the SSH `df`/listing
  probe (Deploy) to browse un-scanned directories. Enabling it on agents requires the ADR-025
  dispatch channel ON (opt-in per its enablement). The Deploy SSH probe rides the existing wizard
  connection.
- Manual entry + `exclude_scope` already let an operator express "include `C:\`, exclude
  `C:\Windows`" before Phase 2 lands; Phase 2 only adds *discovery* of un-scanned paths.

## Alternatives considered

- **Catalogue-only tree (no live browse).** Rejected as the sole answer: cannot show un-scanned
  directories, which is the core ask. Kept as the fast default source.
- **Always-on browse listener on the agent.** Rejected: agents have no inbound port by design; this
  would add an attack surface. The dispatch *pull* channel already exists for exactly this shape.
- **Glob excludes.** Deferred: subtree prefixes cover the stated needs (`C:\Windows`, `/`) with
  simpler, more predictable walker logic.

See [[ADR-025-production-signed-job-dispatch-channel]], [[ADR-026-agent-deployment-subsystem]],
[[ADR-033-agent-config-report-and-override]], [[ADR-029-remote-volume-representation]].

---

## Phase 2 design addendum (2026-06-16) — live directory browse, ACCEPTED

Phase 1 (volume dropdown + catalogue tree + subtree `exclude_scope`) shipped and is live fleet-wide.
This addendum locks the Phase 2 design after an owner interview. **Decisions:** live browse covers
**both the Deploy wizard and enrolled agents**; reach is **anywhere the agent can read** (metadata
only, never contents); gating is **MANAGE_AGENTS + a per-request MFA step-up**; the tree shows
**size + file-count** (catalogue for scanned paths, **bounded live sizing on expand** for un-scanned);
**Windows is included** (shared-Python browse loop, packaged for native install).

**Key correction to the original Phase-2 sketch:** do **NOT** reuse the ADR-025 remediation *listen*
daemon. `build_listener_from_config` is **fail-closed** — it refuses to start without
`write_enabled` + `quarantine_dir` + orchestrator key, because it is the *write* path. Coupling a
read-only browse to it would force the write path on. Instead, model browse on the **read-only
ADR-014 preview grant-serve loop**, which already long-polls, verifies a **pinned core public key**,
serves read-only, and explicitly does **not** require `write_enabled`/`quarantine_dir`.

**Browse-serve loop (agent), mirrors preview grant-serve:**
- New config `browse_grant_pubkey_ref` (a secret-backend *reference* to the core's browse public key,
  never the key — ADR-010), `browse_grant_key_id`. Unset ⇒ the loop never starts (default-off,
  opt-in per host, exactly like `preview_grant_pubkey_ref`).
- When set, the agent runs an always-on `browse-serve` loop: long-poll core → receive a **signed
  `BrowseRequest`** → verify (signature against the pinned key, `expires_at`, `host_id` scope,
  single-use nonce — the same fail-closed order as `verify_job`) → list **one** directory → post the
  result. **Read-only**: it does NOT require `write_enabled`/`quarantine_dir` (the remediation gates).
- The listing returns, per entry: name, `is_dir`, `is_symlink`, own size + mtime, and for child
  directories a **bounded** subtree size + file-count (a walk capped by entry count + a time budget,
  flagged `truncated` when the cap is hit). **No file contents ever cross the channel.** Symlinked
  directories are reported but not traversed. Reach is unrestricted to whatever the agent UID can
  read (owner ruling) — still metadata-only, MFA-gated, and audited.

**Core endpoints:**
- Agent-facing (mTLS, fingerprint-resolved host): `POST /api/v1/agents/browse/poll` (long-poll for a
  signed `BrowseRequest`) and `POST /api/v1/agents/browse/result` (post the listing; consume nonce).
- Operator-facing: `POST /api/v1/agents/{host_id}/browse` — **`MANAGE_AGENTS` + per-request
  `require_step_up_mfa`**, scope-checked to the host, **audited**. Body `{path}`; the core signs a
  `BrowseRequest` with the browse key, enqueues it for the host (reusing the `JobQueue`
  enqueue-and-wait correlation), awaits the agent's result (bounded timeout), returns the listing.
  *Per-request* MFA: every browse call re-checks step-up freshness; the freshness window is
  configurable (`mfa_freshness_seconds`) so it can be relaxed to per-session later without a rebuild.
- Deploy-facing: `POST /api/v1/deployment/browse` — **`DEPLOY_AGENT` + step-up**; runs `df` (volume
  dropdown) and a read-only directory listing + bounded `du` (sizes) **live over the push-SSH
  enrollment connection** (reusing `SshClient.run`), for a not-yet-enrolled host with no catalogue.

**Browse signing key:** a dedicated core Ed25519 browse keypair (generated like the remediation
keygen). The private key stays on the core (signs `BrowseRequest`s); the public key is distributed to
agents as `browse_grant_pubkey_ref`. Distinct from the orchestrator (remediation) key — browse trust
≠ write trust.

**UI:** a reusable lazy `DirTree` (fetch a level on expand; show size + file-count; Include / Exclude
buttons that fill the scan-scope / `exclude_scope` lists). On the **Agents** override it browses the
host live via the operator browse endpoint (and shows catalogue data for already-scanned paths); on
**Deploy** it browses the target via the SSH browse endpoint. The per-request step-up surfaces as the
existing 401 → MFA-prompt → retry flow.

**Windows:** the browse-serve loop is shared Python (works over the Windows/NTFS backend, which
already reports sizes); packaged via the existing PyInstaller spec + a Windows service-install
(listen/serve mode as a Scheduled Task/service) and bundle wiring. Deployed by the operator on the
host (no remote-deploy path to it from the core's network in the pilot).

**Rollout:** generate the browse keypair on the core; distribute the pubkey to agents; add an
always-on `browse-serve` daemon (a small long-poll container, write path off) to each Linux agent
host — **non-disruptive** (it does not trigger scans). Default-off until `browse_grant_pubkey_ref` is
set, so enabling browse is a deliberate per-host step.

**Security posture:** every browse is operator-initiated (MANAGE_AGENTS + step-up), core-signed,
host-scoped, single-use, time-boxed, read-only, metadata-only, and audited. An agent never serves a
browse it cannot cryptographically attribute to the core's browse key. This is strictly weaker than
remediation (no mutation, no `write_enabled`), so it does not arm the write path.
