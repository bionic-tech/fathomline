# SPA static assets (`public/`)

Vite copies everything in this folder to the built `dist/` root verbatim, so files here are served
at the site root (e.g. `public/favicon.ico` → `/favicon.ico`). `index.html` references the favicon
from here.

## Favicon (brand source: `assets/brand/`)
`index.html` links `/favicon.ico` and `/fathomline-icon.svg`, served from this folder. They are
**deploy copies** of the canonical assets in `assets/brand/` (which is outside the Vite project root
and so can't be referenced at runtime). If you update either brand file, re-copy it here:

```
cp ../../../../assets/brand/favicon.ico         ./favicon.ico
cp ../../../../assets/brand/fathomline-icon.svg ./fathomline-icon.svg
```
