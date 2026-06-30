# ADR-042 — Frontend readability (contrast) + tabbed Settings

**Status:** Accepted  **Date:** 2026-06-19  **Deciders:** project owner

## Context

Two operator-reported UX problems on the dark SPA theme:

1. **Readability.** Secondary text (muted descriptions, per-setting help, table column headers, KPI
   sub-labels, breadcrumb separators) used low `slate-400/500/600` greys on the near-black panels.
   On `#171a21` these land around 3–6:1 — borderline or below the WCAG-AA 4.5:1 target for body
   text — so help/description text was hard to read.
2. **Settings sprawl.** The admin Settings page stacked every section vertically — account, ~11
   runtime-setting categories, named secrets, channel test, users — into one long scroll that was
   hard to navigate after the AI/settings suite (ADR-038/039/040) landed.

The brief: **improve readability while staying close to the existing scheme**, and **use tabs** for
the settings sections.

## Decision

- **Contrast lift, same palette.** Raise every secondary-text grey exactly one step
  (`slate-400 → 300`, `500 → 400`, `600 → 500`) in `index.css`. This preserves the visual hierarchy
  (white headings → `slate-100` body → `slate-300` secondary) and the dark theme + accent unchanged,
  but brings muted/help text to AA contrast. No brand colour or layout change.
- **Tabbed Settings via a reusable `Tabs` component** (`features/common/Tabs.tsx`) implementing the
  WAI-ARIA tabs pattern (roles `tablist`/`tab`/`tabpanel`, `aria-selected`, roving `tabIndex`,
  Arrow/Home/End keys, lazy panel mount so heavy panels don't all render).
  - **Settings page** top-level tabs: **Account · Configuration · Users & roles** (last admin-only).
  - **Configuration → Runtime settings** (admin) sub-tabs by category (General & UI, LLM inference,
    AI concierge, … ) plus a **Named secrets** tab; the channel test sits under Notifications.

## Consequences

- Muted/help text is legible; the look is unchanged otherwise (no new colours, accent intact).
- Settings is navigable: one click to a section, no long scroll; lazy panels avoid rendering every
  category table at once.
- A shared, accessible `Tabs` primitive is now available for other multi-section pages (e.g. the
  Deploy wizard's ad-hoc tabs could adopt it later).
- Pure frontend: no API, schema, or engine change; the existing Settings test still passes (the
  default-active Account tab keeps "Your account" visible, non-admins still never see "Users & roles").
