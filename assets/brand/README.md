# Fathomline brand assets

**The code in this repository is licensed under AGPL-3.0. The "Fathomline" name and the logos /
wordmarks / icons in this directory are trademarks of Bionic Technologies Ltd and are _not_ covered
by that licence.** A fork may use the code, but must **remove or replace these brand assets and use a
different name** — do not ship a fork under the Fathomline name or marks. (The `fathom` engine
codename in the source — the package, imports and `FATHOM_*` env vars — is part of the code, not the
brand, and is unaffected.)

These assets live in `assets/brand/` (not `docs/branding/`, which is gitignored and pruned from the
public snapshot) so the shipped marks survive `scripts/release/build-public-snapshot.sh`.

## Tokens
- [`brand-tokens.css`](brand-tokens.css) — canonical Depth Scale palette + font stacks (single source
  of truth; the SPA mirrors it).

## Image / vector assets
The **device-style** look is primary (photoreal, device-led); the **vector-alt** icon + wordmark
cover what a photoreal image can't (a crisp 16 px favicon and the typeset name). Present:

| File | Purpose | Status |
|---|---|---|
| `fathomline-logo.jpeg` | Photoreal device hero (primary mark, 2048²) — README header | ✅ present |
| `fathomline-logo-hdd.jpeg` | HDD device tile (section art) | ✅ present |
| `fathomline-logo-nvme.jpeg` | NVMe device tile | ✅ present |
| `fathomline-logo-usb.jpeg` | USB device tile | ✅ present |
| `favicon.ico` | Multi-size "Plummet" favicon (16/32/48) | ✅ present |
| `fathomline-icon.svg` | Scalable "Plummet" icon (modern browsers) | ✅ present |
| `fathomline-wordmark-dark.svg` | Sora wordmark, light text on dark | ✅ present |
| `fathomline-wordmark-light.svg` | Sora wordmark, dark text on light | ✅ present |

`favicon.ico` + `fathomline-icon.svg` are also copied to `src/fathom/web/public/` (the SPA serves
its favicon from there). If you update either, re-copy it — `assets/brand/` stays the source of truth.
Editable masters + generators are kept privately by Bionic Technologies.
