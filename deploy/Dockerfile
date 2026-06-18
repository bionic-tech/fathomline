# Fathom application image — used by the migrate, api (and later scanner) services.
# Built via `docker compose build` (no published image yet).

# ---------------------------------------------------------------------------
# Stage 0 (optional): build the UI viewer SPA to static assets (ADR-012 supply chain).
# The node toolchain lives ONLY in this build stage; the runtime image never carries node.
# The produced dist/ is COPYed into the runtime image and served same-origin by the api
# container under / (FATHOM_WEB_DIST, src/fathom/api/static.py). In CI prefer building dist
# externally and COPYing it in; this stage keeps a single-command `docker build` working too.
# ---------------------------------------------------------------------------
FROM node:22-slim AS web
WORKDIR /web
COPY src/fathom/web/package.json src/fathom/web/package-lock.json ./
# `npm ci` against the committed lockfile (ADR-012: pinned supply chain).
RUN npm ci --no-audit --no-fund
COPY src/fathom/web/ ./
RUN npm run build

FROM python:3.12-slim AS runtime

# uv for fast, lockfile-pinned installs (matches the repo toolchain).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# Layer 1: dependencies only (cached unless pyproject/lock change).
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev

# Layer 2: the application + migrations.
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
RUN uv sync --frozen --no-dev

# Layer 3: the built SPA static assets (from the node `web` stage). Served same-origin by the
# api under / when FATHOM_WEB_DIST points here (frontend ADD §15, ADR-012). No node in runtime.
COPY --from=web /web/dist ./src/fathom/web/dist

# Drop to a non-root user for the API (the scanner overrides this to uid 0 + a single cap).
RUN useradd --system --uid 10001 --no-create-home fathom
USER 10001

EXPOSE 8080
# Default command = the read/ingest API. The migrate and scanner services override it.
CMD ["uvicorn", "--factory", "fathom.api.app:create_app", "--host", "0.0.0.0", "--port", "8080"]
