"""FastAPI application factory (ADR-007).

The read surface and the agent/write surfaces are mounted as separate routers with
distinct auth dependencies (ADD 01). Schema creation is owned by Alembic in production;
``auto_create_schema`` exists only for dev/test convenience.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import anyio
from fastapi import FastAPI

from fathom.api.routers import (
    admin_users,
    agent_browse,
    agent_jobs,
    agents,
    auth,
    charts,
    concierge,
    config,
    deployment,
    duplicates,
    ingest,
    notifications,
    organize,
    preview,
    preview_pull,
    read,
    reconcile,
    remediation,
    scan_coordinator,
    scans,
    settings_admin,
    suitability,
    worker_render,
)
from fathom.api.security_headers import SecurityHeadersMiddleware
from fathom.api.static import mount_spa

# Import the auth + remediation + preview-cache models so their tables register on the shared
# ``Base.metadata`` (one metadata / one Alembic chain) before ``create_all`` runs under
# auto_create_schema.
from fathom.auth import models as _auth_models  # noqa: F401
from fathom.core.catalogue import embedding_meta as _embedding_meta  # noqa: F401
from fathom.core.catalogue import notification_meta as _notification_meta  # noqa: F401
from fathom.core.catalogue import preview_cache_meta as _preview_cache_meta  # noqa: F401
from fathom.core.catalogue import scan_lease_meta as _scan_lease_meta  # noqa: F401
from fathom.core.catalogue import settings_override_meta as _settings_override_meta  # noqa: F401
from fathom.core.catalogue.models import Base
from fathom.core.db import dispose_engine, init_engine
from fathom.core.remediation import models as _remediation_models  # noqa: F401
from fathom.core.settings import Settings, get_settings
from fathom.logging import configure_logging
from fathom.workers.retention import RetentionWorker


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    engine = init_engine(settings)
    if settings.auto_create_schema:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    # Runtime settings store (ADR-038): the in-app, persistent, encrypted, live-reloaded override
    # layer over the env-seeded Settings. Built from the (env-resolved) encryption key reference —
    # an ephemeral per-process key when unset (dev/test). Loaded from the DB now so the request path
    # (request_settings) immediately sees any persisted overrides; a periodic worker re-reads it so
    # a change made by another worker converges without a restart.
    from fathom.backends.remote import env_or_docker_secret_provider
    from fathom.core.settings_store import RuntimeSettingsStore
    from fathom.workers.settings_refresh import SettingsRefreshWorker

    key_material: str | None = None
    if settings.settings_store_key_ref:
        key_material = env_or_docker_secret_provider(settings.settings_store_key_ref)
    else:
        # No persistent key → from_key_material() mints an EPHEMERAL per-process Fernet key, so
        # every in-app secret (API keys, named secrets, encrypted settings) becomes undecryptable
        # after a restart and silently reverts to its env default. Warn loudly so it never bites.
        from fathom.logging import get_logger

        get_logger("fathom.api.app").warning(
            "settings_store_key_ref is not set — using an EPHEMERAL settings-store key; in-app "
            "secrets will NOT survive a restart. Set FATHOM_SETTINGS_STORE_KEY_REF (ADR-010) to a "
            "stable Fernet key for durable encrypted settings."
        )
    settings_store = RuntimeSettingsStore.from_key_material(key_material)
    app.state.settings_store = settings_store
    from fathom.core.db import session_scope

    async with session_scope() as _session:
        await settings_store.refresh(_session)
    settings_refresh = SettingsRefreshWorker(
        settings_store, interval_seconds=settings.settings_store_refresh_seconds
    )
    settings_refresh.start()
    # Proactive watch worker (ADR-040): always scheduled, self-gates on watch_enabled +
    # notifications_enabled each tick (so toggling is live). Reads the EFFECTIVE settings so
    # thresholds/interval changes apply without a restart; raises capacity / days-to-full alerts
    # into the bell + outbound channels via the store-backed secret provider.
    from fathom.core.settings_store import build_secret_provider
    from fathom.workers.watch import WatchWorker

    watch_worker = WatchWorker(
        settings_provider=lambda: settings_store.effective(settings),
        secret_provider=build_secret_provider(settings_store, env_or_docker_secret_provider),
    )
    watch_worker.start()
    # The signed-job dispatch queue is provisioned unconditionally (ADR-025 §1): it is the core
    # side of the agent-initiated channel. It stays inert when remediation is OFF — no job is ever
    # enqueued, so /agents/jobs/poll always 204s. The write-path runtime that *enqueues* is wired
    # separately and only when remediation_enabled AND a signing key is provisioned (below).
    from fathom.core.remediation.job_queue import JobQueue

    app.state.job_queue = JobQueue()
    # Provision the write-path runtime (signer + queue-backed dispatch) ONLY when remediation is
    # enabled AND a signing key is provisioned by reference (ADR-025 §3, ADR-010). Absent either,
    # the runtime stays unset and get_runtime() 503s — default-OFF is preserved, no silent no-op. A
    # key reference that is set but invalid raises and aborts startup (fail loud, never half-armed).
    from fathom.api.remediation_runtime import build_remediation_runtime

    runtime = build_remediation_runtime(settings, app.state.job_queue)
    if runtime is not None:
        app.state.remediation_runtime = runtime
    # The change_log retention pruner runs as a stdlib-asyncio background task for the API's
    # lifetime (incremental subsystem: change_log is 90-day retention-capped). Off in tests/dev
    # unless explicitly enabled, so an in-memory test catalogue is never pruned mid-suite.
    worker: RetentionWorker | None = None
    if settings.change_log_retention_enabled:
        worker = RetentionWorker(
            interval_seconds=settings.change_log_prune_interval_seconds,
            retention_days=settings.change_log_retention_days,
        )
        worker.start()
    # Concierge embedding worker (ADR-035 Phase 2): default-OFF. Builds + maintains path-name
    # embeddings for semantic search via local Ollama. Requires a pgvector-enabled Postgres in prod;
    # off in tests/dev unless explicitly enabled.
    from fathom.workers.embedding import EmbeddingWorker

    embed_worker: EmbeddingWorker | None = None
    if settings.concierge_embeddings_enabled:
        from fathom.inference.embeddings import build_embedding_provider

        embed_worker = EmbeddingWorker(
            provider=build_embedding_provider(
                settings,
                secret_provider=build_secret_provider(
                    settings_store, env_or_docker_secret_provider
                ),
            ),
            interval_seconds=settings.concierge_embedding_interval_seconds,
            batch=settings.concierge_embedding_batch,
        )
        embed_worker.start()
    # Single-host preview enablement (ADR-014): when the operator has turned preview on AND chosen
    # the single-host topology, provision the runtime at startup with the local-disk fetcher (the
    # data is on this host — no signed remote pull needed). Default-OFF and fail-closed: with
    # preview_local_fetch False the route stays 503 until a distributed runtime is wired the
    # deliberate way. The runsc sandbox driver is built here and refuses to construct unless the
    # configured runtime is 'runsc', so a mis-set runtime fails startup loudly rather than rendering
    # untrusted content under weak isolation (E-7).
    if settings.preview_enabled and settings.preview_local_fetch:
        from fathom.preview.provision import build_local_preview_runtime

        app.state.preview_runtime = build_local_preview_runtime(settings)
    elif settings.preview_enabled:
        # Distributed topology (ADR-014): the core mints + pulls file grants and ships the bytes to
        # a gVisor worker for the render (the core cannot run runsc — TrueNAS, AR-0002). Provisioned
        # only when a grant signing key + worker URL are configured; otherwise the route stays 503.
        # The shared pull queue feeds the agent poll/serve endpoints (preview_pull router).
        from fathom.api.preview_runtime_dist import build_distributed_preview

        provisioned = build_distributed_preview(settings)
        if provisioned is not None:
            app.state.preview_runtime, app.state.preview_pull_queue = provisioned
    # Agent deployment subsystem (ADR-026): default-OFF. Provisioned only when
    # agent_deployment_enabled AND the CA refs resolve; else the routes 503. A configured-but-
    # invalid CA ref raises here and aborts startup (fail loud — never a half-armed deploy surface).
    from fathom.api.deploy_runtime import build_deploy_runtime

    deploy_runtime = build_deploy_runtime(settings)
    if deploy_runtime is not None:
        app.state.deploy_runtime = deploy_runtime
    # Live directory browse (ADR-034 Phase 2): default-OFF. Provisioned only when a browse signing
    # key is configured by reference; else the agent poll/result routes stay inert (204) and the
    # operator browse endpoint 503s. A configured-but-invalid key ref raises here (fail loud).
    from fathom.api.browse_runtime import build_browse_runtime

    browse = build_browse_runtime(settings)
    if browse is not None:
        app.state.browse_signer, app.state.browse_pull_queue = browse
    try:
        yield
    finally:
        await settings_refresh.stop()
        await watch_worker.stop()
        if worker is not None:
            await worker.stop()
        if embed_worker is not None:
            await embed_worker.stop()
        # Drain in-flight push deploys before disposing the engine, so their terminal audit lands
        # and a background task can't re-init the engine from its finally (use-after-dispose;
        # ADR-026 round-5 F2). Guarded — the runtime only exists when deployment is provisioned.
        deploy_runtime = getattr(app.state, "deploy_runtime", None)
        if deploy_runtime is not None:
            await deploy_runtime.drain()
        await dispose_engine()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the Fathom core API application."""
    configure_logging()
    cfg = settings or get_settings()
    app = FastAPI(
        title="Fathomline API",
        version="0.2.0",
        summary="The storage-estate analyzer — read/query surface, agent ingest, and the "
        "default-OFF write/deploy surfaces.",
        description=(
            "HTTP API for Fathomline (built on the Fathom engine). The read/query routes are "
            "RBAC- and scope-gated; the agent ingest routes authenticate by mTLS client-cert "
            "fingerprint behind the proxy; the remediation, preview and deployment surfaces are "
            "default-OFF and individually gated. See the project docs for auth and deployment."
        ),
        lifespan=_lifespan,
    )
    app.state.settings = cfg
    # Strict CSP (no unsafe-inline/eval) + hardening headers on every response (ADD §12).
    app.add_middleware(SecurityHeadersMiddleware)
    app.include_router(ingest.router)
    # The signed-job dispatch routes (ADR-025): same mTLS + fingerprint boundary as ingest, NOT
    # human SSO. Inert by default — poll 204s until a write-path runtime enqueues a job.
    app.include_router(agent_jobs.router)
    app.include_router(read.router)
    app.include_router(charts.router)
    app.include_router(duplicates.router)
    app.include_router(scans.router)
    app.include_router(agents.router)
    # Scan concurrency coordinator (ADR-036): the agent-facing lease endpoint (mTLS) + the operator
    # advisory read surface (VIEW_METADATA). Inert until scan_coordinator_enabled (grants-all).
    app.include_router(scan_coordinator.router)
    # Notification Center (ADR-031): the in-app "bell" read/dismiss surface. Read-only,
    # VIEW_METADATA + scope, default-OFF behind notifications_enabled.
    app.include_router(notifications.router)
    # Suitability / onboarding (ADR-037): per-host AI-option traffic-lights from reported hardware
    # facts. Read-only, VIEW_METADATA + scope.
    app.include_router(suitability.router)
    # Read-only server feature-flag view for the Settings page (VIEW_METADATA; secret-free).
    app.include_router(config.router)
    # Content-aware Organize suggestions (ADR-021): read-only, default-OFF (organize_enabled),
    # VIEW_METADATA + scope gated. The gated *apply* rides the remediation surface (ADR-023).
    app.include_router(organize.router)
    # AI concierge (ADR-035): read-only natural-language Q&A over the catalogue, default-OFF
    # (concierge_enabled), VIEW_METADATA + scope gated. The model only picks a closed-enum tool;
    # the server runs the scoped query and decides what the principal may see.
    app.include_router(concierge.router)
    # Cross-host reconciliation (ADR-024): read-only divergence detection, VIEW_METADATA + scope.
    app.include_router(reconcile.router)
    # The sandboxed preview surface (ADR-014): PREVIEW-capability + scope gated, default-OFF,
    # derived-artifact-only. A separate read-class route; never returns raw bytes.
    app.include_router(preview.router)
    # Distributed-preview agent pull channel (ADR-014): agents long-poll for signed file grants and
    # serve one file's bytes back. Inert (204/409) until the distributed preview runtime is wired.
    app.include_router(preview_pull.router)
    # Live directory browse (ADR-034 Phase 2): agent poll/result (inert until the browse runtime is
    # wired) + the operator browse endpoint (MANAGE_AGENTS + per-request step-up MFA, audited).
    app.include_router(agent_browse.router)
    # The gVisor render worker route (ADR-014): active only on a worker instance
    # (preview_worker_enabled); 503 on the core. Carries bytes to the sandbox, returns artifacts.
    app.include_router(worker_render.router)
    app.include_router(auth.router)
    app.include_router(admin_users.router)
    # Runtime settings administration (ADR-038): read/edit the in-app settings store.
    # MANAGE_SETTINGS (admin) for all routes; the secret routes (reveal / set-secret) also
    # require step-up MFA.
    app.include_router(settings_admin.router)
    # The Write/Action surface is a SEPARATE route group from read/ingest (ADD 01, AR-0003):
    # every route is destructive-capability + (for execute/quarantine) step-up-MFA gated, and
    # refuses unless remediation_enabled. The read-only hash-chained audit route rides alongside.
    app.include_router(remediation.router)
    app.include_router(remediation.audit_router)
    # Agent deployment surface (ADR-026): DEPLOY_AGENT + step-up-MFA gated, default-OFF (503 until
    # provisioned). The bundle-redeem sub-route is token-gated, not human-auth — by design.
    app.include_router(deployment.router)

    @app.get("/healthz", tags=["meta"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # Serve the built SPA same-origin under / (history fallback) only when configured
    # (ADR-012). Mounted last so its catch-all fallback never shadows the API routers.
    if cfg.web_dist:
        mount_spa(app, anyio.Path(cfg.web_dist))

    return app
