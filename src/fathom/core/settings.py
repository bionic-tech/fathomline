"""Core settings (pydantic-settings, env-driven).

Secrets never live in code or a committed file (Framework Principle #8, ADR-010); they
arrive via the environment / Docker secrets / OpenBao at runtime. This model only declares
shape and safe defaults for non-secret wiring.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process configuration, populated from ``FATHOM_*`` environment variables."""

    model_config = SettingsConfigDict(env_prefix="FATHOM_", extra="ignore")

    # SQLAlchemy async URL. Prod: postgresql+asyncpg://… on Patroni (ADR-003).
    # The default is an in-process SQLite for local/dev and tests only.
    database_url: str = "sqlite+aiosqlite:///:memory:"

    # Maximum number of fs_entry rows accepted in a single ingest batch (DoS guard, AR-0012).
    ingest_max_batch: int = Field(default=5000, ge=1)

    # Shared secret the mTLS-terminating proxy sets on every forwarded ingest request, proving
    # the request transited that boundary. Without it the core would trust the
    # ``X-Client-Cert-Fingerprint`` header on a DIRECT call that bypassed the proxy, letting
    # anyone reachable on the ingest port forge an agent identity (AR-0010/AR-0020, STRIDE
    # Spoofing). Injected at runtime via env/Docker secret (ADR-010); when unset (dev/test) the
    # check is OFF — PRODUCTION MUST SET IT. A startup check warns loudly if ingest runs without it.
    ingest_proxy_secret: str | None = None

    # SQL echo for debugging (never on in prod).
    db_echo: bool = False

    # Create ORM tables on startup — dev/test only; Alembic owns the schema in prod.
    auto_create_schema: bool = False

    # --- Runtime settings store (ADR-038) ------------------------------------------------
    # *Reference* into the secret backend (ADR-010) for the Fernet key that encrypts in-app SECRET
    # settings + named secrets at rest — never the key itself (urlsafe-base64, resolved at runtime
    # via env / Docker secret). When unset (dev/test) an ephemeral per-process key is generated: the
    # store still encrypts, but encrypted secrets do NOT survive a restart. PRODUCTION MUST SET IT
    # if any secret is stored in-app. Non-secret overrides are JSON (plaintext) and always durable.
    settings_store_key_ref: str | None = None
    # How often the in-process store re-reads the DB override-set (seconds) so a change made by
    # another worker/process propagates without a restart (live reload across workers). The writing
    # worker refreshes immediately; this is the cross-worker convergence interval.
    settings_store_refresh_seconds: float = Field(default=15.0, gt=0)

    # --- Human auth + RBAC (ADD 13, ADD 03 §2; ADR-009/010) ----------------------------
    # Provider chain order, local-first per owner ruling. Unknown names are ignored.
    auth_providers: tuple[str, ...] = ("local", "forward", "oidc")
    # Server-side session lifetime (seconds); sessions are short-lived and revocable.
    session_ttl_seconds: int = Field(default=43200, ge=60)  # 12h absolute
    # Step-up MFA freshness window for destructive write routes (ADD 13 §4).
    mfa_freshness_seconds: int = Field(default=300, ge=30)
    # Trusted reverse-proxy source CIDRs for forward-auth header trust. Empty = trust none
    # (fail-closed): forward-auth is disabled until an operator configures the proxy source.
    trusted_forward_proxy_cidrs: tuple[str, ...] = ()
    # Non-secret OIDC wiring (issuer + public client id). The client secret is injected at
    # runtime via env/Docker secret/OpenBao and is never declared here (ADR-010).
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    # Emit the session cookie with Secure (HTTPS-only). Disable only for local http dev.
    session_cookie_secure: bool = True

    # --- UI viewer: static SPA serving + chart node caps (ui-viewer, frontend ADD §10/§15)
    # Absolute path to the built SPA's ``dist/`` directory. When unset the api serves only
    # ``/api/v1`` and ``/healthz`` — the static mount is OFF (the SPA is fronted elsewhere in
    # dev). When set, the api serves the SPA same-origin with history fallback (ADR-012:
    # built in a node stage and COPYed in, never built at runtime).
    web_dist: str | None = None
    # Hard server-side node cap for the treemap/sunburst endpoint — the browser cannot ask
    # for more (frontend ADD §10 risk: ECharts cannot ingest a 50M-node tree → OOM).
    treemap_max_nodes: int = Field(default=200, ge=1, le=2000)
    # Max items the top-N 'biggest offenders' endpoint will return.
    top_n_max: int = Field(default=100, ge=1, le=1000)
    # Max points a downsampled growth series returns (server-side downsample, ADD §10).
    growth_max_buckets: int = Field(default=500, ge=2, le=5000)

    # First-run onboarding (Build P4): a single estate-wide flag, flipped True the moment ANY admin
    # finishes the Getting Started setup wizard. While False the wizard auto-shows as a first-run
    # MODAL to admins (and the standalone nav link is offered); once True it never auto-shows and the
    # nav link is hidden. Editable via the settings store so an admin can re-arm it (set it back to
    # False) from Settings — it is otherwise inert (no behaviour hangs off it server-side).
    onboarding_completed: bool = False

    # --- Remediation write path (ADR-011, remediation-enable; default OFF) ---------------
    # The master server-side gate. Remediation build/dry-run/execute routes refuse to act
    # unless this is True AND the target agent's write_enabled is True. Flipping it is a
    # deliberate, documented runbook step — never a code default (security_constraints).
    remediation_enabled: bool = False
    # Server-authoritative blast-radius cap: the orchestrator refuses an EXECUTE over this
    # many items without an explicit confirm flag (E-1). The agent's own copy is never the
    # authority (AR-0012).
    remediation_blast_cap: int = Field(default=100, ge=1)
    # Signed-job validity window (seconds). A job not consumed within this expires (T-3).
    remediation_job_ttl_seconds: int = Field(default=300, ge=30)
    # Job-signing algorithm (owner ruling: Ed25519 for non-repudiation; hmac-sha256 fallback).
    remediation_signing_algorithm: str = "ed25519"
    # *Reference* into the secret backend for the orchestrator signing key (ADR-010). Never the
    # key itself — the key material is injected at runtime via Docker secret / OpenBao.
    remediation_signing_key_ref: str | None = None
    # Trusted key id the actor pins for the orchestrator's signing key (non-secret identifier).
    remediation_signing_key_id: str = "orchestrator-v1"
    # Quarantine retention before an item is purge-eligible (ADR-011: 7 days).
    quarantine_retention_days: int = Field(default=7, ge=1)

    # --- Preview worker (preview-worker, ADR-014; default OFF) ---------------------------
    # Master gate: the preview route refuses unless this is True AND a runtime is provisioned.
    # Like remediation_enabled, flipping it on is a deliberate runbook step (ADR-014, AR-0002).
    preview_enabled: bool = False
    # Single-host topology switch (preview-worker): when True, the preview runtime is provisioned
    # at startup with the local-disk file fetcher (LocalFileFetcher) instead of the distributed
    # signed single-file pull — the data is on this host, so no agent round-trip is needed. The
    # runsc sandbox is identical either way; only the byte source differs. Still default-OFF and
    # only takes effect when preview_enabled is also True. Distributed deployments leave this False
    # and wire the signed-pull fetcher via the documented enablement step.
    preview_local_fetch: bool = False
    # The Docker/runsc runtime name the sandbox driver requires (AR-0002 residual-label foot-gun:
    # the driver refuses to run if this is not 'runsc', so a silent fall back to runc voids the
    # isolation argument — STRIDE E-7). Set to "" only in tests that inject a fake driver.
    preview_sandbox_runtime: str = "runsc"
    # The hardened preview-worker sandbox image the driver spawns per render.
    preview_sandbox_image: str = "fathom-preview:local"
    # Per-render resource caps — the bomb/DoS guard (STRIDE D-6). Owner-set concrete limits:
    # one CPU, 512 MiB RAM, 10s wall-clock, 50 pages, 100 MiB max-decompressed.
    preview_cpu_limit: float = Field(default=1.0, gt=0)
    preview_mem_bytes: int = Field(default=512 * 1024 * 1024, ge=64 * 1024 * 1024)
    preview_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    preview_max_pages: int = Field(default=50, ge=1, le=500)
    preview_max_decompressed_bytes: int = Field(default=100 * 1024 * 1024, ge=1024 * 1024)
    # Largest raw input the worker will accept for a render (a coarse pre-sandbox guard); a file
    # over this is rejected with a sanitised problem+json rather than streamed to the sandbox.
    preview_max_input_bytes: int = Field(default=256 * 1024 * 1024, ge=1024)
    # Encrypted, bounded-LRU derived-artifact cache (STRIDE I-8; data-protection §3/§4/§7). The
    # cache holds NO raw bytes — only encrypted DERIVED artifacts — bounded by entry count and a
    # 30-min TTL (whichever evicts first).
    preview_cache_ttl_seconds: int = Field(default=1800, ge=60)  # 30-min TTL (ADR-014)
    preview_cache_max_entries: int = Field(default=256, ge=1)
    # *Reference* into the secret backend for the cache-encryption key (ADR-010). Never the key
    # itself — the urlsafe-base64 Fernet key is injected at runtime via Docker secret / OpenBao.
    # When unset, an ephemeral per-process key is generated (dev/test only): the cache is still
    # encrypted, but the key does not survive a restart (acceptable for a 30-min TTL cache).
    preview_cache_key_ref: str | None = None
    # Signed single-file pull (owner ruling): the gVisor worker requests exactly ONE file by a
    # nonce'd, short-TTL, scope-checked grant over the agent-initiated mTLS channel. This is the
    # grant's validity window (seconds); a grant not redeemed within it expires (STRIDE T-3).
    preview_grant_ttl_seconds: int = Field(default=60, ge=5, le=600)
    # --- Distributed preview (ADR-014): core mints+pulls, a separate gVisor worker renders -------
    # *Reference* into the secret backend for the core's Ed25519 grant SIGNING key (private). When
    # set together with preview_worker_url (and preview_local_fetch is False), the core provisions
    # the DISTRIBUTED preview runtime: it mints/signs file grants for agents to serve, and ships the
    # bytes to the worker. Agents pin the matching PUBLIC key (agent preview_grant_pubkey_ref).
    preview_grant_signing_key_ref: str | None = None
    preview_grant_key_id: str = "preview-v1"
    # The URL the core POSTs render jobs to (the worker's /api/v1/preview/render). The core cannot
    # run runsc itself (TrueNAS, AR-0002), so the gVisor render happens here.
    preview_worker_url: str | None = None
    # Set True ONLY on the gVisor worker instance: it mounts a functional /preview/render route
    # (runs RunscSandboxDriver). The core leaves this False — its /render returns 503.
    preview_worker_enabled: bool = False
    # --- Live directory browse (ADR-034 Phase 2): operator-driven, read-only, MFA-gated -------
    # *Reference* into the secret backend for the core's Ed25519 BROWSE signing key (private),
    # DISTINCT from the orchestrator/preview keys (browse trust ≠ write trust). When set, the core
    # provisions the browse runtime: the operator browse endpoint signs a BrowseRequest, the owning
    # agent (which pins the matching PUBLIC key via browse_grant_pubkey_ref) lists one directory and
    # serves it back. Absent the ref, the agent poll/result routes stay inert (204) and the operator
    # browse endpoint 503s — default-OFF.
    browse_signing_key_ref: str | None = None
    browse_grant_key_id: str = "browse-v1"
    # The browse request validity window (seconds); a request not served within it expires (T-3).
    browse_request_ttl_seconds: int = Field(default=30, ge=5, le=300)

    # --- Agent deployment subsystem (ADR-026; default OFF) -------------------------------
    # Master gate: the deployment routes (push SSH-deploy + pull enrollment) refuse unless this
    # is True AND the CA signing material is provisioned. Flipping it on is a deliberate runbook
    # step — it gives core an (optional, gated) SSH-out capability + the CA signing key (ADR-026).
    agent_deployment_enabled: bool = False
    # *References* into the secret backend (ADR-010) for the Fathom CA used to mint agent client
    # certs — never the material itself. The cert (public) and key (private, signing) are resolved
    # at runtime via env / Docker secret. Absent either, the runtime stays unset and routes 503.
    agent_deployment_ca_cert_ref: str | None = None
    agent_deployment_ca_key_ref: str | None = None
    # Minted client-cert validity (days), matching deploy/mint-agent-cert.sh (825 = ~27 months).
    agent_deployment_cert_days: int = Field(default=825, ge=1, le=3650)
    # The proxy ingest URL baked into a deployed agent's config (the mTLS terminator it pushes to).
    agent_deployment_ingest_url: str = "https://proxy:9443/api/v1/agents/ingest"
    # Server-wide defaults for the wizard's per-request fields: the IP/hostname deployed agents
    # map "proxy" to (compose extra_hosts), and the core base URL baked into the pull-bootstrap
    # command. Both are deployment-specific, so the product ships no default — a request may pass
    # them explicitly; otherwise these must be set or the route 422s (fail-loud, never a baked-in
    # address).
    agent_deployment_proxy_host_ip: str | None = None
    agent_deployment_core_base_url: str | None = None
    # The agent container image tag the deploy transfers/loads on the target.
    agent_deployment_image: str = "fathom:local"
    # Optional path (in the core container — a mounted volume) to a ``docker save | gzip`` archive
    # of the agent image. When set, a fresh target with no image is bootstrapped from it: pull mode
    # serves it at /deployment/image and the bootstrap loads it; push streams it over SFTP +
    # ``docker load``. The image is not secret, but the endpoint still requires a live enrollment
    # token (ADR-026). Unset = the image is assumed already present on the target (v1 default).
    agent_deployment_image_archive_path: str | None = None
    # Bounded concurrency for a batch deploy run (mirrors the preview worker's shed-load gate).
    agent_deployment_max_concurrent: int = Field(default=3, ge=1, le=16)
    # Pull-mode enrollment-token validity window (seconds): a one-time signed token a target
    # redeems to fetch its bundle. Short by design (single-use + TTL, STRIDE T-3).
    agent_deployment_enroll_ttl_seconds: int = Field(default=900, ge=60, le=3600)

    # --- LLM inference + content-aware Organize (ADR-021/022/023; default OFF) ------------
    # Master gate: the Organize routes refuse unless this is True. Like remediation/preview,
    # flipping it on is a deliberate step. The write half (apply) additionally rides the
    # remediation gates (remediation_enabled + EXECUTE_REMEDIATION + step-up MFA).
    organize_enabled: bool = False
    # The inference provider ALL chat features use (Organize + Concierge) — one provider, applied
    # everywhere (ADR-022). 'ollama' = local, on-host, no egress (default); 'openai'/'anthropic' =
    # cloud, opt-in behind the egress gate. Embeddings are configured separately (a chat provider
    # like Anthropic may not offer an embeddings API), see concierge_embedding_provider.
    inference_provider: str = "ollama"
    # The chat model id ALL chat features request from that provider (e.g. 'llama3.2:3b' for ollama,
    # 'claude-haiku-4-5' for anthropic). Set this once with the provider and everything uses it.
    inference_model: str = "llama3.2:3b"
    # OPTIONAL per-feature model overrides — blank/None means "use inference_model". Kept for the
    # rare case of a different model per feature; leave unset for one cohesive model everywhere.
    organize_model: str | None = None
    # Local Ollama base URL (no trailing slash).
    inference_ollama_url: str = "http://127.0.0.1:11434"
    # Hard per-request inference timeout (seconds) — caps a slow/runaway model (STRIDE D-6). LLM
    # structured-generation over a folder of files is not instant; 120s suits a small local model.
    inference_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    # Egress gate: the cloud provider REFUSES to construct unless this is True (ADR-022). Default
    # False keeps content-derived digests on-host; turning it on is a deliberate data-egress choice.
    inference_allow_egress: bool = False
    # OpenAI-compatible endpoint + *reference* into the secret backend for its API key (ADR-010,
    # never the key itself). Only used when inference_provider='openai' AND egress is allowed.
    inference_openai_url: str = "https://api.openai.com/v1"
    inference_openai_key_ref: str | None = None
    # Direct API key (entered in the UI, masked, stored ENCRYPTED as a secret setting). The easy
    # path — paste the key, done. Preferred over the *_key_ref above; the ref stays for external
    # secret backends (Docker secrets / env). Only used when provider='openai' AND egress allowed.
    inference_openai_api_key: str | None = None
    # Anthropic Messages API (ADR-022 cloud path): base URL + *reference* into the secret backend
    # for the API key (ADR-010, never the key). Only used when inference_provider='anthropic' AND
    # egress is allowed. Structured output is obtained via a forced single-tool call (schema as the
    # tool input_schema), then re-validated like every other provider.
    inference_anthropic_url: str = "https://api.anthropic.com"
    inference_anthropic_key_ref: str | None = None
    # Direct API key (UI, masked, stored ENCRYPTED as a secret setting) — the easy path; preferred
    # over the *_key_ref above (which stays for external secret backends). anthropic + egress only.
    inference_anthropic_api_key: str | None = None
    inference_anthropic_version: str = "2023-06-01"  # Anthropic API version header (non-secret).

    # --- AI Concierge (ADR-035; default OFF) ---------------------------------------------
    # Master gate: the concierge query route refuses unless this is True. Like organize/preview,
    # flipping it on is a deliberate runbook step. The concierge is READ-ONLY — it answers natural-
    # language questions over the catalogue via a closed set of scope-enforcing query tools; it
    # never mutates the catalogue or the filesystem, and the model has no authority (it picks a tool
    # + params from a closed enum; the server runs the query and decides what the principal sees).
    concierge_enabled: bool = False
    # OPTIONAL concierge model override — blank/None = use inference_model (the cohesive default).
    concierge_model: str | None = None
    # Max catalogue rows fed to the narration step (bounds prompt size + latency).
    concierge_context_max_rows: int = Field(default=50, ge=1, le=500)
    # --- Concierge semantic search (ADR-035 Phase 2; pgvector; default OFF) ---------------
    # Build + maintain file-path embeddings so the concierge can answer fuzzy "find by meaning"
    # queries. Default OFF so no deployment pays the embedding cost unless it wants semantic search
    # (it needs a pgvector-enabled Postgres image). Independent of concierge_enabled: the structured
    # concierge works without it; this only adds the optional semantic_search tool. Metadata-only:
    # the pipeline embeds file NAMES + path tails, never file content.
    concierge_embeddings_enabled: bool = False
    # Which embedding provider backs semantic search (ADR-035 addendum). 'ollama' = local, no egress
    # (default); 'voyage' (Anthropic's preferred embedder) and 'openai' are cloud — opt-in behind
    # the same egress gate as chat. The operator commits to one provider + dimension at deploy (the
    # dimension fixes the vector column; switching later is a deliberate reindex).
    concierge_embedding_provider: str = "ollama"
    # Embedding endpoint override (no trailing slash). Ollama: defaults to inference_ollama_url.
    # Voyage: https://api.voyageai.com. OpenAI: https://api.openai.com/v1. Leave unset for defaults.
    concierge_embedding_url: str | None = None
    # *Reference* into the secret backend for the cloud embedder's API key (ADR-010; never the key).
    # Only used when the provider is a cloud one AND egress is allowed.
    concierge_embedding_key_ref: str | None = None
    # Direct embedder API key (UI, masked, stored ENCRYPTED as a secret setting) — the easy path;
    # preferred over the *_key_ref above. Only used for a cloud embedder (voyage/openai) + egress.
    concierge_embedding_api_key: str | None = None
    # The embedding model the provider requests. Ollama 'nomic-embed-text' produces 768-dim vectors;
    # Voyage 'voyage-4-lite' is 1024-dim; OpenAI 'text-embedding-3-small' is 1536-dim.
    concierge_embedding_model: str = "nomic-embed-text"
    # Vector dimension the embedding column is sized to — MUST match the model (nomic=768).
    concierge_embedding_dim: int = Field(default=768, ge=1, le=4096)
    # Embedding worker cadence + per-tick batch cap (bounds the backfill + steady-state load).
    concierge_embedding_interval_seconds: float = Field(default=300.0, gt=0)
    concierge_embedding_batch: int = Field(default=512, ge=1, le=10000)

    # --- Incremental change-feed retention (ADR-006, incremental subsystem) --------------
    # Run the change_log retention pruner as an in-process background task. OFF by default so a
    # dev/test in-memory catalogue is never pruned mid-suite; the production compose enables it.
    change_log_retention_enabled: bool = False
    # Churn retention window (incremental owner ruling: 90 days). Rows older than this are pruned.
    change_log_retention_days: int = Field(default=90, ge=1)
    # How often the pruner runs (seconds); default daily — far below the 90d window so a missed
    # tick (restart) never loses retention correctness.
    change_log_prune_interval_seconds: float = Field(default=24 * 60 * 60, gt=0)

    # --- Scan concurrency coordinator (ADR-036; default OFF) ------------------------------
    # Master gate: the agent scan-lease endpoint grants UNCONDITIONALLY unless this is True (so the
    # feature is inert until deliberately enabled). When on, a HEAVY scan is DEFERRED while another
    # heavy scan holds a lease, so the core is never hit by two big reconcile/finalize passes at
    # once (the failure mode that motivated this — concurrent heavy scans saturating Postgres). It
    # only coordinates WHEN a scan runs; it never changes WHAT a scan sees.
    scan_coordinator_enabled: bool = False
    # How many heavy scans may hold a lease at once (1 = strictly serialize heavy scans fleet-wide).
    scan_coordinator_max_concurrent_heavy: int = Field(default=1, ge=1)
    # A scan is "heavy" when the host's last run saw >= this many entries (the dominant driver of
    # the core's reconcile/finalize cost). A host with no prior run is treated as heavy
    # (conservative — an unproven host's first full scan is coordinated rather than assumed light).
    scan_coordinator_heavy_entries: int = Field(default=500_000, ge=1)
    # Lease lifetime (seconds). A heavy scan can run for hours, so a lease is normally released when
    # the agent reports its run; this TTL is the CRASH safety net — a dead agent's lease expires
    # after it. Default 6h covers the largest fleet scans; raise for very large estates.
    scan_coordinator_lease_ttl_seconds: int = Field(default=6 * 60 * 60, ge=60)
    # The retry-after (seconds) a deferred agent is advised to wait before its next attempt.
    scan_coordinator_retry_after_seconds: int = Field(default=30 * 60, ge=60)

    # --- Notification Center (ADR-031; default OFF) --------------------------------------
    # Master gate: the in-app notification ("bell") routes refuse unless this is True, and the SPA
    # hides the bell. Producers (scan-coordinator, scan-health, capacity, audit, the suitability
    # watcher) only emit when it is on. Read-only — notifications never write the estate. Outbound
    # Email/Chat channels are wired in a later wave; Phase 1 is the in-app center only.
    notifications_enabled: bool = False
    # Retention for delivered/read notifications (days); a pruner trims older rows so the bell
    # store stays bounded. Unread rows past this are kept (you should still see what you missed).
    notification_retention_days: int = Field(default=30, ge=1)

    # --- Notification outbound channels (ADR-039; default OFF) ---------------------------
    # Everything lands in the in-app bell; these settings govern the EXTRA fan-out to Email/Chat.
    # Which categories fan out (a subset of recommendation|problem|activity|security). Default: the
    # two that usually warrant a push. The in-app bell still receives every category regardless.
    notify_outbound_categories: tuple[str, ...] = ("problem", "security")
    # Minimum severity that fans out to the channels (info|warning|critical). Default 'warning' so
    # routine info never pages anyone; the bell still shows info. A note must clear BOTH this and
    # the category filter to be sent outbound.
    notify_min_severity: str = "warning"
    # Hard per-send timeout (seconds) for an outbound channel — a slow SMTP/webhook never blocks the
    # producer for long; a failed/slow send is logged and swallowed (the bell row is already there).
    notify_send_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    # Email (SMTP) channel. The password is a *reference* into the secret backend (ADR-010) — the
    # value is stored as a named secret (encrypted, ADR-038), never here. STARTTLS by default.
    notify_email_enabled: bool = False
    notify_email_smtp_host: str | None = None
    notify_email_smtp_port: int = Field(default=587, ge=1, le=65535)
    notify_email_use_tls: bool = True  # STARTTLS after connect
    notify_email_username: str | None = None
    notify_email_password_ref: str | None = None
    notify_email_from: str | None = None
    notify_email_to: tuple[str, ...] = ()
    # Chat channel (one webhook-style target). The webhook URL (Discord/Slack) or bot token
    # (Telegram) is a *reference* into the secret backend — stored as a named secret (encrypted).
    notify_chat_enabled: bool = False
    notify_chat_kind: str = "discord"  # discord | slack | telegram
    notify_chat_webhook_ref: str | None = None
    notify_chat_telegram_chat_id: str | None = None  # required for telegram (the destination chat)

    # --- Proactive watch (ADR-040; default OFF) ------------------------------------------
    # Master gate for the proactive watcher: a background worker re-assesses the estate on an
    # interval and posts capacity / days-to-full alerts to the bell (+ channels). The worker is
    # always scheduled but self-gates on this flag each tick, so toggling it is LIVE (no restart).
    # Effective only when notifications_enabled is also on (the bell is the delivery surface).
    watch_enabled: bool = False
    # How often the watcher re-assesses (seconds); default hourly. Read live each loop.
    watch_interval_seconds: float = Field(default=60 * 60, gt=0)
    # Volume fullness thresholds (percent of capacity) for the warning / critical capacity alerts.
    watch_capacity_warn_percent: int = Field(default=90, ge=1, le=100)
    watch_capacity_critical_percent: int = Field(default=97, ge=1, le=100)
    # Days-to-full horizon: a volume forecast to fill within this many days raises an alert.
    watch_days_to_full_warn: int = Field(default=14, ge=1, le=3650)
    # Stale-scan alert: a host whose most recent COMPLETED scan is older than this many hours raises
    # a problem alert. A silently-failing nightly writes NO agent_run row, so the age simply grows —
    # that is exactly the signal (nas-1 went 11 days unnoticed because the cron swallowed errors).
    # 0 disables. Default 36h tolerates one missed nightly + slop. Hosts that never scanned are not
    # flagged (no run history yet); "agent offline" is a separate concern.
    watch_scan_stale_hours: int = Field(default=36, ge=0, le=8760)


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
