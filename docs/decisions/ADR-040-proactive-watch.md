# ADR-040 — Proactive watch: re-assess the estate and alert the bell

**Status:** Accepted  **Date:** 2026-06-19  **Deciders:** project owner

## Context

The Notification Center (ADR-031) + channels (ADR-039) can deliver alerts, and the concierge can
*answer* "how full are my disks / when will this fill?" on demand (ADR-035 `growth_forecast`). But a
disk analyzer that only answers when asked still lets you walk into a full disk. The owner's design
interview chose **"watch and proactively notify"**: a background watcher that periodically
re-assesses the estate and **pushes** problems/recommendations to the bell — the proactive half of
the onboarding/suitability story (ADR-037) and the TODO's P2 ("days-to-full" capacity alerts).

## Decision

A **stdlib-asyncio watch worker** (no broker, mirroring the retention worker) plus a small **pure
rules module** (`core/watch.py`) that turns catalogue state into `WatchAlert`s, each with a stable
`dedup_key` so a persisting condition coalesces in the bell instead of restacking every tick.

**Rules (v1):**
- **Capacity** — per volume, `used/total ≥ warn%` → warning, `≥ critical%` → critical. Computed from
  the live `Volume` row (no history needed). `dedup_key = capacity:vol=<id>`.
- **Days-to-full** — reuses the concierge's `growth_forecast` (linear fit over `size_history`); a
  volume forecast to fill within `watch_days_to_full_warn` days raises a warning. Best-effort per
  volume (a forecast failure never suppresses the capacity alerts). `dedup_key = forecast:vol=<id>`.

**Worker.** Always scheduled at startup but **self-gating** each tick on `watch_enabled` +
`notifications_enabled`, and it reads the **effective** settings (ADR-038) — so enabling/disabling
the watcher and changing thresholds/interval are **live, no restart**. Each alert is raised with
`emit_and_dispatch` (ADR-039): the bell row is the source of truth, outbound channels are best-effort
on top. A tick that raises is logged and swallowed so one failed sweep never kills the loop.

**Settings** (`watch_*`, in the settings-store allow-list, all live): the gate, the interval, the
warn/critical capacity percents, and the days-to-full horizon.

## Consequences

- **Proactive, not just reactive:** capacity + days-to-full problems reach the operator without
  anyone opening the app or asking the concierge.
- **No restart to tune:** the always-on/self-gating worker + effective-settings read make the whole
  feature live-configurable from the Settings page.
- **Bell-first, fail-soft:** every alert is recorded in the bell even if a channel send fails;
  dedup keys keep a steady-state condition to a single, refreshed entry.
- **Reuses, not forks:** the forecast is the concierge's, delivery is ADR-031/039, config is ADR-038.
  No new tables; one new worker + one rules module.
- **v1 scope:** capacity + days-to-full. Scan-health, hardware-change and AV-appeared rules
  (ADR-037) are natural follow-on `WatchAlert` producers in the same engine.
