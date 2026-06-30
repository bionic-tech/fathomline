# Fathomline — TODO (proposed backlog)

**Status:** Proposed — **nothing here is approved to build yet.** Every item is gated on an
**ADR design** (next free number: **ADR-044**) before any code is written.
**Last updated:** 19 June 2026
**Companion to:** [`ROADMAP.md`](ROADMAP.md) · ADRs in [`docs/decisions/`](docs/decisions/)

> These items are **not** on `ROADMAP.md` — they are candidate features captured for review.
> The rationale and full write-up live in the product roadmap doc
> (`FATHOMLINE_ROADMAP_2026-06-19.md`, §5). Each one extends something already built; none
> should start until its ADR is written and accepted.

---

## How to read this

| Field | Meaning |
|---|---|
| **Gate** | The ADR that must be written + accepted **before** build. ADR numbers are reserved here but the ADRs do **not** exist yet. |
| **Leans on** | The existing subsystem / ADR this builds on (so it's incremental, not greenfield). |
| **Effort** | Rough size: S (days), M (1–2 wks), L (multi-wk / new collector). |

**Workflow for any item:** write the ADR → accept it → design doc (if UI/schema) → build →
test → update `ROADMAP.md`. Reserve the ADR number when you start, not before.

---

## Priority 1 — first public milestone (build these first)

These five turn "a disk analyzer" into "the safe, estate-wide storage guardian that warns you
before you run out **and** before you delete your only copy."

| # | Item | Gate (ADR) | Leans on | Effort |
|---|---|---|---|---|
| ~~**P1**~~ ✅ | **Wire real notification channels** — **DELIVERED** ([ADR-039](decisions/ADR-039-notification-channels.md)): Email (SMTP) + Discord/Slack/Telegram, per-category + severity policy, bell UI, admin test-send. *Remaining: ntfy, Gotify, generic webhook (a thin add on the same `NotifyTransport`).* | **ADR-039** | Notification Center (ADR-031) | M |
| ~~**P2**~~ ✅ | **Proactive capacity alerts ("days-to-full")** — **DELIVERED** ([ADR-040](decisions/ADR-040-proactive-watch.md)): the watch worker raises capacity + days-to-full alerts to the bell + channels, coalesced + live-configurable. | **ADR-040** | `growth_forecast` (ADR-035); delivery from P1 | S–M |
| **P3** | **Single-copy / restore-risk detector** — flag files that exist in only one place on the estate ("this file has no second copy"). Inverts the dedup index. Data-loss-prevention, not cleanup. | **ADR-044** | Cross-host dedup index (BLAKE3 grouping) | M |
| **P4** | **Distribution: TrueNAS SCALE app + Unraid Community App + Helm chart** — package the existing container for the homelab storefronts. | **ADR-045** | Existing container build (ADR-013) | M |
| **P5** | **S.M.A.R.T / disk-health correlation** — pull drive health and join to content: "this *failing* disk holds your only copy of X." Build after P3; only if the collector is cheap. | **ADR-046** | P3 (single-copy index) + new health collector | L |

---

## Priority 2 — adjacent, second wave (low risk, high homelab/SMB fit)

> A9 + A10 are small but expected product gaps. A9 (dev-cache reclaim) is the more on-brand:
> regenerable-cache reclaim is a natural, low-risk first use of the remediation spine.


| # | Item | Gate (ADR) | Leans on | Effort |
|---|---|---|---|---|
| **A4** | **Prometheus exporter + Grafana dashboard** — per-host capacity, growth rate, reclaimable bytes. | **ADR-047** | Catalogue queries; existing metrics surfaces | S–M |
| **A5** | **Stale-data / retention reports** — "files untouched in 2+ years", "largest never-read files". Pure query over the catalogue. | **ADR-048** | Catalogue (atime/mtime already held) | S |
| **A7** | **Scheduled scans + scan calendar UI** — "scan the NAS nightly, workstations weekly". Pairs with the scan coordinator. | **ADR-049** | Scan Concurrency Coordinator (ADR-036) | M |
| **A8** | **Per-share / per-user quota reporting for SMB** — "who's filling the share". | **ADR-050** | SMB backend (already enumerates shares) | M |
| **A9** | **Dev-cache reclaim badges** — classify regenerable dev caches (`node_modules`, `.gradle`, `target`, `__pycache__`, etc.), badge them, roll up reclaimable bytes. Low-risk first remediation case (quarantine-first delete of a known-regenerable cache). | **ADR-056** | Catalogue (path patterns) + remediation spine (ADR-011/019/023) | S–M |
| **A10** | **JSON / CSV data export** — `?format=csv\|json` on the read endpoints (duplicates report, largest files, listing) via `StreamingResponse`. | **ADR-057** | Existing read endpoints | S |

---

## Priority 3 — ambitious bets (flag as exploratory)

| # | Item | Gate (ADR) | Leans on | Effort |
|---|---|---|---|---|
| **B2** | ***arr-stack & media-app awareness** (Sonarr/Radarr/Jellyfin/Immich/Nextcloud) — identify orphaned media, app-managed vs loose files. Keep **read-only enrichment** to contain scope creep. | **ADR-051** | Catalogue + new read-only app integrations | L |
| **B3** | **Cloud-cost view for rclone remotes** — "this bucket ≈ £X/mo; here's the cold/duplicate spend". | **ADR-052** | rclone backend (ADR-028/029) + pricing data | L |
| **B4** | **Home Assistant / MQTT free-space sensors** — publish per-host free space to HA. Tiny effort, big homelab goodwill. | **ADR-053** | Catalogue free-space metrics | S |
| **B5** | **Community "Organize" rule packs** — shareable rules for the inference/Organize subsystem. Builds network effects once public dev lands. | **ADR-054** | Organize subsystem (ADR-021) | M |
| **B6** | ⚠️ **Managed / hosted Fathomline (SaaS control plane)** — **decide deliberately.** Tension with the OSS-gift ethos; only if it funds the free product, never to paywall it. | **ADR-055** (decision-only) | Whole platform | L+ |

---

## Notes

- **ADR numbers 044–057 are reserved, not written.** Don't assume any design exists yet.
- **B6 is a strategy decision, not a feature** — its ADR should record the call (build / don't
  build / defer), not a design.
- **P5 (B1) and P3 (A6)** are intentionally sequenced: the single-copy index (P3) is a
  prerequisite for the failing-disk correlation (P5).
- Keep the safety spine intact: anything that *acts* on files (vs. reports) must ride the
  existing signed + quarantine-first + audited remediation pipeline (ADR-011/019/023) — none of
  the above currently does, and that's deliberate.

---

*Proposed backlog — Bionic Technologies Ltd · Fathomline. Review, accept, or bin per item.*
