# ADR-037 — Onboarding & suitability wizard ("Getting Started")

**Status:** Accepted (design)  **Date:** 2026-06-19  **Deciders:** project owner

## Context

The AI concierge (ADR-035) and its semantic search exposed a real adoption problem: an operator
can't easily tell whether a given machine can actually run a given AI option. Embedding an entire
large estate at full precision can want tens of GB of vector-index RAM — fine on a beefy box,
impossible on a 32 GB one — and which local chat model fits depends on GPU VRAM / CPU. Today nothing
guides that choice, and nothing flags the mundane things that break a *scan* either (Wi-Fi vs
Ethernet, antivirus, clashing backups, VLAN/firewall routing to the core). The audience is a **broad
mix** (homelab hobbyists through to less-technical home users and small business), so the product
needs to do the thinking for a newcomer while letting an expert opt out.

Two constraints shape it: (1) **agents may not be deployed yet**, so the wizard must be able to
reach a host with operator-supplied **credentials (password *or* SSH key)** — reusing the deploy
wizard's SSH path (ADR-026) — *and* use the agent once one exists; (2) the manual deploy path must
remain for people who dislike wizards.

## Decision

A single, re-usable **"Getting Started" wizard** that does as much automatically as it can, presents
choices as **traffic-lights with a "best for you" pick**, and surfaces results into the
**Notification Center** (ADR-031). It does not replace the manual Deploy screen — it wraps and
extends it (ADR-026), and stays available for later add/rebuild/replace-machine flows.

**Flow:** connect to host(s) (SSH **password or key**, pre-agent; or via the agent if enrolled) →
**hardware probe** (auto-detect CPU / RAM / GPU / disks, shown on a confirm screen the user can
correct) → **suitability**: for each AI option (local small/large chat model, local vs cloud
embeddings, semantic-search index size) show ✅ fits / ⚠️ slow / ❌ won't-fit + one recommended pick,
driven by the cost/model research (`docs/research/concierge-inference-cost-analysis.md`) → **scan
pre-flight**: flag network type/speed, antivirus (suggest an agent exclusion), clashing heavy jobs +
good scan windows (feeds the scan coordinator, ADR-036), and VLAN/firewall reachability to the core
→ **deploy** agents (the existing ADR-026 mechanism) → **recommend** concrete AI settings (model +
embedder + dimension) the operator can accept or tweak.

**Proactive re-assessment:** a background watcher periodically re-checks (hardware changed, a disk
filled, AV appeared, a host was added) and posts **recommendations / problems to the bell** rather
than waiting for the user to re-run the wizard.

**Shared building blocks (build once, reuse):**
- **Host-facts reporting** — a small new agent capability to report CPU cores / RAM / GPU(+VRAM)
  (disks already come from `Volume`); used by both the wizard and the watcher.
- **Suitability/traffic-light engine** — pure logic mapping (host facts → estate size → cost/latency
  → ✅/⚠️/❌ + recommended model/embedder/dimension). Reused by the concierge's model picker (ADR-035
  addendum) so the wizard and the concierge agree.
- **Notification Center** (ADR-031) — the delivery surface for recommendations and warnings.

## Consequences

- **Default-friendly, never wizard-only:** the guided flow is the obvious newcomer path; the manual
  Deploy screen and a "skip — I'm an expert" exit always remain.
- **Re-usable:** the same wizard handles first-run *and* later add/rebuild/swap-host events.
- **New surfaces/work:** the agent host-facts probe; the SSH path gains **password auth** (ADR-026 is
  key-only today); the suitability engine; the watcher; wizard UI. Read-only and gated like every
  other optional subsystem.
- **Privacy:** credentials are used transiently for probing/deploy (never stored beyond the documented
  deploy-secret handling); the suitability engine sends nothing off-host.
- **Dependencies / sequence:** builds on the **Notification Center** (ADR-031) and the shared
  suitability engine; pairs with the concierge embedder/model work (ADR-035 addendum). Its own
  feature branch, expanding ADR-026.

## Out of scope (here)
Cloud-cost billing/quotas beyond a pre-enable estimate; auto-purchasing cloud capacity; phone/push
notifications (ADR-031 defers these). The wizard *recommends*; the operator decides.
