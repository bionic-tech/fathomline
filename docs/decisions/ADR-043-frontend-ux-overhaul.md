# ADR-043 — Frontend UX overhaul (GUI review 2026-06-20)

**Status:** Accepted  **Date:** 2026-06-20  **Deciders:** project owner

## Context

A UI review (`docs/reviews/Gui-reviews/2026-06-20/fathomline-ui-report.md`) found recurring
readability and semantics problems on the dark theme, plus two owner asks. The findings:

- **Colour carried no consistent meaning.** Status/result badges were ad-hoc — Agents showed `idle`
  in **red** (a normal resting state read as an error), and every Audit result was the same red, so
  a success looked identical to a dispatch.
- **Low-contrast secondary UI** — placeholders, helper text and disabled controls were near
  invisible; the active tab combined a background tint *and* an underline.
- **The volume-capacity chart** used the hardest-to-separate blue-on-amber pair, a low-contrast
  legend, and a flat x-axis of raw volume names with no way to tell which **machine** a bar belonged
  to (and basenames like `root` repeat across hosts).
- **Scroll-heavy pages** (esp. the Dashboard) stacked many panels vertically.
- Owner asks: make the **concierge** a floating contextual sidebar (see
  [ADR-035 addendum](ADR-035-ai-concierge.md)), and **hide the navigation page URLs**.

This builds on [ADR-042](ADR-042-frontend-readability-tabbed-settings.md) (the contrast lift + the
`Tabs` component + tabbed Settings), generalising those decisions across the app.

## Decision

- **One semantic colour system.** Five tokens — success / info / warning / danger / neutral — as
  badge classes (and shared chart hues), applied via a single `lib/badge.ts` map from a
  status/result string to a class. **Red is reserved for genuine failures only:** a resting state
  (`idle`) is neutral, an in-flight state (dispatched/pending) is amber, a plain fact (set/built) is
  blue, success/served/ok is green. Fixes the Agents + Audit badges.
- **Contrast (AA).** Carried over from ADR-042 and completed: a global `::placeholder` colour,
  coloured helper text, a clearer disabled-button affordance (not just opacity), and a **single**
  active-tab treatment (accent underline, no competing background).
- **Host-grouped, colour-blind-safe capacity chart.** Recolour to teal **Used** over muted steel
  **Free** (consumption emphasis, drops blue-on-amber); lift the legend/axis text. **Group volumes
  by host** so a machine's disks sit together, with a per-host dotted band (`markArea`, per-host
  hue) and a colour-matched host-name label — so a bar's machine is unambiguous despite repeated
  basenames. Tooltip shows host · volume · used % + sizes.
- **Tabs for scroll-heavy pages.** Roll out the ADR-042 `Tabs` pattern wherever a page stacks
  genuinely independent sections:
  - **Dashboard** — three heavy chart panels (Volume capacity / Composition / Growth trend) become
    tabs, KPI summary pinned above.
  - **Duplicates** — *Content duplicates* / *Cross-cloud*; the cross-cloud (provider-hash) tab is
    added **only when there is something to show** (estates without rclone keep the flat table).
  - **Scans** — *History* / *Deep scan*; the heavy deep-scan request form moves off the default
    view (operators only — read-only viewers still see just the history table).
  - **Reconcile** — *Compare* / *Results*; a completed comparison auto-focuses Results (via a
    `resultKey` remount) so a long form and a long table never stack.
  - **Audit** — *Log* / *Integrity*; the hash-chain explanation + continuity check move to their own
    tab, the pager stays in the Log tab (a broken-chain alert still surfaces in the header).
  - **Deploy** keeps its existing Push/Pull **mode** tabs (already a tablist; switching clears the
    other mode's half-entered SSH secrets — not converted to lazy `Tabs`).
  - **Judgement — kept inline:** **Largest** (a single compact toolbar of instant-feedback toggles
    over one table — no second section to tab without breaking the feedback loop) and **Agents**
    (per-host config is an in-row disclosure; promoting it to a top-level tab would need a host
    picker and add clicks, so the expand pattern stays).
- **In-memory routing to hide navigation URLs.** The SPA uses `createMemoryRouter` (start entry
  `/`), so navigation never touches the address bar and the route paths (`/dashboard`, `/settings`,
  …) are not exposed. The auth guard + login already navigate in-app, so the flow is unchanged.

## Consequences

- **Colour always means the same thing**, and false-alarm reds are gone; new badges should use the
  semantic classes / `lib/badge.ts`.
- **The capacity chart answers "whose disk is this?"** at a glance and is legible for colour-blind
  users.
- **Less scrolling** across the scroll-heavy pages; the shared `Tabs` primitive now serves Settings,
  Dashboard, Duplicates, Scans, Reconcile and Audit (with two reasoned inline exceptions above).
- **URLs are hidden — with a deliberate trade-off:** a full browser **refresh resets to the start
  entry** (no deep-linking or bookmarking a page); the guard re-runs whoami and lands on the
  dashboard (or `/login`). Owner-accepted; revertible to `createBrowserRouter` (or `createHashRouter`)
  if deep-linking is later wanted.
- Pure frontend (plus the concierge `page` hint field) — no schema/engine change. Deployed to the
  core; every new feature remains default-OFF.

## 2026-06-23 addendum — MFA QR code + provider-aware Settings

Two owner asks from a Settings/Account review:

- **Scannable MFA enrolment.** The TOTP enrolment step previously showed only the secret string for
  manual entry — the deliberate choice (recorded in the component) was to **never route the secret
  through an external QR service**. Now the otpauth URI is rendered as a QR code **client-side** with
  `qrcode.react` (in-browser SVG), so a phone can scan it while the secret still never leaves the
  page — the no-leak posture is preserved, not traded away. Manual secret/URI entry stays behind a
  "Can't scan?" disclosure for accessibility. (Adds one pinned frontend dependency, `qrcode.react`,
  per the ADR-012 supply-chain stance.)
- **Provider-aware, decluttered LLM-inference Settings.** The model/embedder fields became
  provider-tracking dropdowns/comboboxes and inapplicable settings are now **hidden rather than
  greyed** — the substantive change lives in the policy layer; see
  [ADR-038 addendum](ADR-038-runtime-settings-store.md) and
  [ADR-022 addendum](ADR-022-pluggable-inference-provider.md) (one cohesive `inference_model`).

Pure frontend; deployed to the core on branch `claude/ui-overhaul`.
