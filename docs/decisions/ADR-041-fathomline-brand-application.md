# ADR-041 — Fathomline brand application & asset/token policy

**Status:** Accepted  **Date:** 2026-06-19  **Deciders:** project owner

## Context

The repository is published as the open-source product **Fathomline** (built on the **Fathom**
engine codename) by **Bionic Technologies**. Brand assets (logo, wordmarks, icon, favicon) and the
project story were authored in a separate private business workspace and needed bringing into the
repo so the public README + SPA carry the identity. Three constraints shaped how:

1. The release pipeline (`scripts/release/build-public-snapshot.sh`) **prunes `docs/branding/`** and
   most of `docs/`, so anything that must *ship* cannot live in a pruned/gitignored path.
2. The engine codename is load-bearing in code (`fathom` package, `FATHOM_*` env vars, imports) and
   must **not** be renamed — only product-name prose/UI is "Fathomline".
3. The SPA enforces a **strict CSP** (`'self'`), which blocks third-party webfonts by default.

## Decision

- **Asset home = `assets/brand/`** (plus `docs/img/` for shipped doc images), never `docs/branding/`.
  `assets/` is copied verbatim by the snapshot, so the marks ship; `docs/STORY.md` was added to the
  snapshot keep-list so the story ships too.
- **One token source.** `assets/brand/brand-tokens.css` is the canonical Depth Scale palette + font
  stacks; the SPA mirrors the variables in `index.css` `:root` and references them as named Tailwind
  colours, so the hex lives in one place.
- **Fonts via Google Fonts, CSP widened minimally.** Sora/Inter/JetBrains Mono load from Google
  Fonts; the CSP gains exactly two origins (`fonts.googleapis.com` for `style-src`,
  `fonts.gstatic.com` for `font-src`) and nothing else. The SPA falls back to system font stacks if
  those are ever removed (self-hosting is the stricter alternative).
- **Trademark posture (forks).** The **code is AGPL-3.0**, but the *Fathomline name and logos are
  trademarks of Bionic Technologies Ltd and are NOT licensed to forks* — a fork must remove/replace
  the brand assets and use a different name. Recorded in `assets/brand/README.md`. The `fathom`
  engine codename is code, not brand, and is unaffected.
- **Cross-brand hygiene.** The public story does not name Bionic's commercial sibling product; the
  snapshot privacy gate still blocks that name, so it cannot leak into the public repo.

## Consequences

- The README renders the photoreal hero + tagline ("Fathomline — sound out your storage estate.") +
  "by Bionic Technologies"; the SPA shows the favicon + brand fonts; the docs index + story carry the
  identity. All shipped from non-pruned paths.
- A single, documented token source keeps the UI + any future docs theme consistent.
- The CSP trade-off (two font origins) is explicit and reversible; security posture is otherwise
  unchanged (no `unsafe-inline`/`unsafe-eval`, everything else `'self'`).
- Forking is legally clear: take the code, drop the marks, rename.
- Engine internals untouched, so no code churn or migration risk from branding.
