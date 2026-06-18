# ADR-016: Single-host and distributed deployment topologies

**Status:** Accepted **Date:** 2026-06-06 **Deciders:** project owner

## Context

Fathom must run two ways from **one codebase**: a **distributed fleet** (core on the NAS host,
data hosts running agents, a separate gVisor preview worker on a dedicated worker node — ADR-002,
ADR-014, the preview-worker deployment runbook) **and** a **single host** where core, data, and the preview worker
sit on one box (`scripts/localdev/README.md` stands the whole stack up on SQLite against real
local directories; `deploy/localhost/PREVIEW.md` is its preview runbook).

The only part of the system that actually differs between the two topologies is **how the
preview worker obtains the one untrusted file it is about to render**. Everything else about a
preview — the RBAC scope gate, audit-before-serve, the runsc sandbox, the encrypted
derived-artifact cache — is invariant (ADR-014). In the distributed case the worker is on a
different host than the data, so the file arrives via the **signed single-file pull over the
agent-initiated mTLS channel**: a nonce'd, short-TTL, host-scoped, Ed25519-signed `FileGrant`
redeeming exactly one file by `(volume_id, inode, content_hash)` — no new agent inbound port,
no broad data mount (the preview-worker deployment runbook; `src/fathom/preview/grant.py`;
`preview_grant_ttl_seconds` in `src/fathom/core/settings.py`). On a single host that round-trip
is pointless: the file is already on local disk.

The pivot point is the `FileFetcher` Protocol (`src/fathom/preview/service.py`): the
`PreviewService` calls `fetcher.fetch(entry, max_bytes=...)` for exactly one file on a cache
miss and is otherwise agnostic to where the bytes came from. The service derives the cache key,
sniffs magic bytes, drives the sandbox, and caches the derived artifact identically regardless
of fetcher (it never decodes content itself and never returns raw bytes). So the topology
choice reduces to **which `FileFetcher` implementation is wired in** — a one-line provisioning
difference, not a forked render path.

## Decision

Support **both single-host and distributed deployment from the same codebase**, isolating the
entire topology difference behind the `FileFetcher` abstraction.

- **Distributed** wires the signed single-file pull fetcher via the documented enablement step:
  `build_preview_runtime(settings, fetcher=..., cache_key_material=...)` in
  `src/fathom/preview/provision.py`, where the caller-supplied fetcher mints and redeems the
  `FileGrant` over the live agent channel (the preview-worker deployment runbook, "Worker process").

- **Single-host** wires `LocalFileFetcher` (`src/fathom/preview/local_fetch.py`) via
  `build_local_preview_runtime(settings)` in `src/fathom/preview/provision.py`. That function is
  identical to `build_preview_runtime` except it passes `fetcher=LocalFileFetcher()` — same
  cache, same `RunscSandboxDriver`, same `PreviewQueue`, same `ResourceCaps`. **Only the byte
  source differs.**

- **The local read keeps the distributed pull's hedges.** `LocalFileFetcher._read` acts only on
  the server-resolved catalogue path/inode (never client-supplied — I-7), opens
  `O_RDONLY | O_NOFOLLOW` (a swapped symlink yields `ELOOP` → 404, never a redirected read),
  re-checks the opened fd's inode against the catalogue's (`st.st_ino != entry.inode` → 409:
  the file was replaced since the scan — TOCTOU / path-swap), and reads at most `max_bytes + 1`
  so the service's input cap (413) still trips without buffering more than the cap. The bytes
  only ever flow on to the sandbox driver, preserving the read != return boundary (ADR-014).

- **The sandbox and everything downstream are unchanged.** Both runtimes build the same
  `RunscSandboxDriver(image=..., runtime=settings.preview_sandbox_runtime)`, which **fails
  closed if the runtime is not `runsc`** (STRIDE E-7), so neither topology can silently render
  untrusted content under `runc`. There is no unsandboxed single-host fast path. The RBAC
  PREVIEW-capability + scope gate, audit-before-serve, and the encrypted bounded-LRU 30-min-TTL
  cache holding no raw bytes (STRIDE I-8) are identical either way
  (`deploy/localhost/PREVIEW.md`, "Why preview still needs gVisor even single-host").

- **Default-OFF, fail-closed enablement.** The single-host path is gated by **two** booleans in
  `src/fathom/core/settings.py`, both default `False`: `preview_enabled` (the master gate, like
  `remediation_enabled`) and `preview_local_fetch` (the topology switch). The lifespan hook in
  `src/fathom/api/app.py` provisions `app.state.preview_runtime` via `build_local_preview_runtime`
  **only when `preview_enabled and preview_local_fetch`** (`src/fathom/api/app.py`, lifespan).
  The route gate is **two-staged**, in order: `get_preview` calls `_require_enabled(settings)`
  first, which raises **`403`** ("preview is disabled (`preview_enabled=False`)") whenever
  `preview_enabled` is `False`; only once that passes does it call `get_preview_runtime(request)`,
  which raises **`503`** ("preview runtime not provisioned") when no runtime is on `app.state`
  (`src/fathom/api/routers/preview.py` lines 51-57 and 146-147; `src/fathom/api/preview_runtime.py`
  lines 33-41). So under the default both-flags-`False` posture the route returns **`403`, not
  `503`** — `503` only appears once `preview_enabled=True` but no runtime has been provisioned.
  This holds in both topologies: the route is `403` until `preview_enabled=True`, then `503` until
  a runtime is provisioned (single-host: the lifespan hook provisions only when `preview_enabled`
  **and** `preview_local_fetch` are both `True`; distributed: until the signed-pull runtime is
  wired the deliberate way, per the preview-worker deployment runbook). Operators opt single-host in with
  `FATHOM_PREVIEW_ENABLED=true` + `FATHOM_PREVIEW_LOCAL_FETCH=true`
  (`deploy/localhost/PREVIEW.md`, "Turn it on"); distributed deployments leave
  `preview_local_fetch` `False`. (`deploy/localhost/PREVIEW.md` line 46-47 simplifies this to
  "stays `503`"; the code is authoritative and the two-stage `403`-then-`503` order above is what
  actually ships.)

### Alternatives considered

- **Distributed-only (no single-host fetcher) — rejected.** Forcing the signed pull on a
  single box demands a second host (or a self-loopback agent channel) and a grant
  mint/redeem round-trip purely to read a file that is already on local disk — machinery with
  no security benefit when there is no network hop to protect. It would also block the
  `scripts/localdev` single-machine workflow that runs the real ingest/render code against
  genuine local data.

- **An unsandboxed single-host fast path — rejected.** Reading the local file and decoding it
  outside runsc "because it's just localhost" voids the entire ADR-014 isolation argument: the
  preview path deliberately reintroduces decoding of untrusted content (PDF/Office/image
  decoders — historically the richest CVE source), and the safety case rests **entirely** on
  the sandbox holding (`deploy/localhost/PREVIEW.md`). The driver therefore fails closed off
  `runsc` (E-7) in both topologies; there is deliberately no shortcut that renders bytes under
  plain `runc`.

## Consequences

### Positive

- One render pipeline, one sandbox, one cache, one audit/RBAC gate for both topologies — the
  topology fork is a single injected `FileFetcher`, so the security-critical code is exercised
  identically whether deployed on a fleet or a laptop.
- The single-host path keeps every distributed hedge (`O_NOFOLLOW`, inode-anchoring, bounded
  read, server-resolved path), so collapsing the network hop does not weaken the file-fetch
  threat model.
- A true single-machine deployment (`scripts/localdev`, `deploy/localhost/PREVIEW.md`) drops
  the second host and the grant round-trip while running the same render and isolation code.

### Negative

- Two `FileFetcher` implementations and two provisioning entry points to keep behaviourally
  aligned; a hedge added to one (e.g. a new fd check) must be mirrored or consciously scoped to
  the other.
- gVisor (`runsc`) is mandatory even single-host — the one root-requiring prerequisite
  (`deploy/localhost/PREVIEW.md`, the preview-worker gVisor install script) — so "single host" is not
  "zero setup": there is no unsandboxed dev mode.

### Risks

- **Silent fall back to `runc`** (STRIDE E-7) — the AR-0002 residual-runtime-label foot-gun
  applies to both topologies. Mitigated by `RunscSandboxDriver` refusing to construct unless
  `preview_sandbox_runtime == "runsc"` and the install probe that fails loudly unless gVisor is
  live (the preview-worker deployment runbook, Step 1).
- **Local-disk TOCTOU / path-swap** — the file at the catalogue path may have changed since the
  scan. Mitigated by `O_NOFOLLOW` + the inode re-check in `LocalFileFetcher._read` (409 on
  mismatch), mirroring the grant's `(volume_id, inode, content_hash)` binding.
- **Mis-enabled topology** — `preview_local_fetch` left `True` on a host that is *not* the data
  host would read the wrong local disk. Mitigated by default-OFF + fail-closed (the route is
  `403` until `preview_enabled=True`, then `503` until a runtime is provisioned; single-host the
  lifespan hook provisions only when both flags are `True`) and the deliberate, documented
  per-topology enablement step; distributed deployments leave the flag `False` and wire the
  signed-pull fetcher instead.
- Threat coverage for the preview surface as a whole is tracked under ADR-014 / STRIDE
  **T-6, I-7, I-8, D-6, E-7**; each ≥ P2 finding gets a named regression test
  (e.g. `test_sandbox_runtime_is_runsc`).
