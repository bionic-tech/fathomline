# Fathom UI viewer (web)

A Vite + React + TypeScript SPA giving a TreeSize-class view over the estate: a toggleable
**Dashboard ⇄ Explorer** shell, ECharts treemap/sunburst/bar/pie + growth line, drill-down
tree, and a (placeholder) sandboxed preview pane. Charting is **Apache ECharts** (ADR-005,
owner ruling). See `docs/architecture/01-frontend-architecture.md`.

## How it is served

The built static assets (`dist/`) are **COPYed into the api image** (ADR-012 supply chain — no
node toolchain in the runtime image) and served by the **same FastAPI api container**,
same-origin under `/` with SPA history fallback (`src/fathom/api/static.py`). `/api/v1` is
unaffected. Serving is guarded entirely behind the `FATHOM_WEB_DIST` env var — unset, the api
serves only `/api/v1` + `/healthz`.

```
# build the SPA
npm ci
npm run build            # → src/fathom/web/dist

# serve it from the api (same origin)
FATHOM_WEB_DIST=/path/to/src/fathom/web/dist \
  uvicorn --factory fathom.api.app:create_app
```

## Develop

```
npm run dev              # Vite dev server; proxies /api → http://localhost:8088 (the api)
npm run typecheck        # tsc --noEmit (strict)
npm run lint             # eslint (no console.*; use lib/csp.ts DEV helpers)
npm run test             # Vitest (ChartAdapter option builders + DataTable a11y)
npm run gen:api          # regenerate typed client from the api's /openapi.json
```

## Security posture (frontend ADD §12)

- **No tokens/content in browser storage** — the session is an httpOnly Secure cookie; client
  state is in-memory (TanStack Query + Zustand). `logout()` clears all client storage.
- **Strict CSP** (no `unsafe-inline` / `unsafe-eval`) is sent as a header by the api
  (`SecurityHeadersMiddleware`); the build introduces no inline script/style.
- **No raw file bytes** are ever requested or rendered — the preview pane shows derived
  artifacts only, via the separate sandboxed worker (ADR-014).
- **Scope-aware** rendering — only in-scope hosts/volumes are shown (the server enforces too).
- Source maps off in prod; all `console.*` gated to DEV.
- Every chart ships a **data-table alternative** (WCAG 2.1 AA).
