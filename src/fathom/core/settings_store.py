"""Runtime settings store (ADR-038) — in-app, persistent, encrypted, live-reload configuration.

Fathom's :class:`~fathom.core.settings.Settings` is env-seeded and immutable for the process. This
store lets an operator override a setting **in-app, without a restart**, and persist it: a stored
override wins over the env default (*in-app value wins; env seeds the default*). The effective
settings are recomputed by overlaying the overrides on the live base and **re-validating** through
the same pydantic model, so an out-of-range value can never be persisted.

Three pieces:

* :class:`SettingPolicy` + :data:`SETTING_POLICIES` — the per-field policy (category, editable,
  secret, restart-required, help). It is the allow-list: only a key with an *editable* policy may be
  set, and only a key flagged *secret* is stored encrypted.
* :class:`RuntimeSettingsStore` — holds the decoded overrides + a monotonic version, builds the
  effective :class:`Settings` (cached by base-identity + version), and resolves named secrets. It
  encrypts secret values at rest (Fernet, the preview-cache precedent) and decrypts only on the
  admin-only, step-up-gated reveal path.
* :func:`build_secret_provider` — composes the store in front of the env/Docker secret provider so a
  secret typed into the UI (e.g. an LLM API key) resolves by reference exactly like an env secret
  (ADR-010), letting an operator get running without touching the host environment.

Live reload: the request path reads the effective settings per request (immediate). Settings whose
effect is bound at startup (a provisioned worker/runtime, the DB URL) are flagged
``restart_required`` so the UI tells the operator a restart is needed — the override still persists.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from cryptography.fernet import Fernet
from sqlalchemy import CursorResult, delete, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.catalogue.settings_override_meta import (
    SETTINGS_VERSION_ID,
    SettingsOverride,
    SettingsVersion,
)
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.core.settings_store")

# Setting categories (the UI groups by these; stable identifiers, not display labels).
CATEGORY_GENERAL = "general"
CATEGORY_INFERENCE = "inference"
CATEGORY_CONCIERGE = "concierge"
CATEGORY_ORGANIZE = "organize"
CATEGORY_REMEDIATION = "remediation"
CATEGORY_PREVIEW = "preview"
CATEGORY_SCAN = "scan_coordinator"
CATEGORY_NOTIFICATIONS = "notifications"
CATEGORY_RETENTION = "retention"
CATEGORY_INGEST = "ingest"
CATEGORY_AUTH = "auth"


@dataclass(frozen=True)
class SettingPolicy:
    """Policy for one configurable setting — the allow-list entry the store + UI consult."""

    key: str
    category: str
    editable: bool = True
    is_secret: bool = False
    restart_required: bool = False
    help: str = ""
    # Optional human label (defaults to a humanised key); a closed option set for a dropdown; and a
    # relevance gate: tuples of (other_key, allowed_values) — the setting only applies when EVERY
    # named key currently holds one of its allowed values (e.g. anthropic settings only when the
    # provider is anthropic). Used to disable irrelevant settings in the UI.
    label: str | None = None
    options: tuple[str, ...] | None = None
    relevant_when: tuple[tuple[str, tuple[object, ...]], ...] | None = None
    # Tuck this setting behind an "Advanced" disclosure in the UI (e.g. a secret-backend *reference*
    # that most operators don't need now that the key can be entered directly).
    advanced: bool = False


# Acronyms that should stay upper-cased when humanising a snake_case key into a label.
_ACRONYMS = {
    "ai",
    "api",
    "cpu",
    "csv",
    "db",
    "gpu",
    "id",
    "ip",
    "json",
    "llm",
    "mfa",
    "ram",
    "smtp",
    "ssh",
    "tls",
    "ttl",
    "ui",
    "url",
    "uid",
    "gid",
}


def humanize(key: str) -> str:
    """Snake_case key → human label ('inference_provider' → 'Inference Provider')."""
    return " ".join(w.upper() if w in _ACRONYMS else w.capitalize() for w in key.split("_"))


def _p(key: str, category: str, **kw: Any) -> SettingPolicy:
    return SettingPolicy(key=key, category=category, **kw)


# The curated allow-list of in-app-manageable settings (ADR-038). Anything not here is env-only
# (deep infra / secret references stay managed by ADR-010), shown read-only by the API. ``editable``
# gates writes; ``restart_required`` means the override persists but takes full effect only after a
# restart (the value is bound at startup — a provisioned worker/runtime or the DB engine).
_POLICY_LIST: tuple[SettingPolicy, ...] = (
    # --- General / UI caps (live) ---
    _p("treemap_max_nodes", CATEGORY_GENERAL, help="Server-side node cap for treemap/sunburst."),
    _p("top_n_max", CATEGORY_GENERAL, help="Max items the 'biggest offenders' endpoint returns."),
    _p("growth_max_buckets", CATEGORY_GENERAL, help="Max points a downsampled growth series."),
    _p(
        "onboarding_completed",
        CATEGORY_GENERAL,
        label="Onboarding completed",
        help="Estate-wide first-run flag. True once an admin finishes the setup wizard; set it "
        "back to False to re-arm the first-run wizard for the next admin login.",
    ),
    # --- Auth (live: read per request) ---
    _p("mfa_freshness_seconds", CATEGORY_AUTH, help="Step-up MFA freshness window (seconds)."),
    _p("session_ttl_seconds", CATEGORY_AUTH, help="Session lifetime (applies to new logins)."),
    # --- Ingest ---
    _p("ingest_max_batch", CATEGORY_INGEST, help="Max fs_entry rows accepted in one ingest batch."),
    _p(
        "ingest_proxy_secret",
        CATEGORY_INGEST,
        is_secret=True,
        help="Shared secret the mTLS proxy sets on forwarded ingest requests (read per request).",
    ),
    # --- LLM inference (live: provider built per request) ---
    _p(
        "inference_provider",
        CATEGORY_INFERENCE,
        label="Inference provider",
        options=("ollama", "openai", "anthropic"),
        help="The chat backend ALL AI features use: ollama (local) | openai | anthropic.",
    ),
    _p(
        "inference_model",
        CATEGORY_INFERENCE,
        label="Inference model",
        help="The chat model ALL AI features request from the provider "
        "(e.g. claude-haiku-4-5 for anthropic, llama3.2:3b for ollama). Set once, used everywhere.",
    ),
    _p(
        "inference_allow_egress",
        CATEGORY_INFERENCE,
        label="Allow cloud egress",
        relevant_when=(("inference_provider", ("openai", "anthropic")),),
        help="Egress gate: must be on for any cloud provider (sends prompts off-host).",
    ),
    _p("inference_timeout_seconds", CATEGORY_INFERENCE, help="Hard per-request inference timeout."),
    _p(
        "inference_ollama_url",
        CATEGORY_INFERENCE,
        label="Ollama URL",
        relevant_when=(("inference_provider", ("ollama",)),),
        help="Local Ollama base URL (no trailing /). Used by the ollama chat + embedder.",
    ),
    _p(
        "inference_openai_url",
        CATEGORY_INFERENCE,
        label="OpenAI endpoint URL",
        relevant_when=(("inference_provider", ("openai",)),),
        help="OpenAI-compatible endpoint base URL.",
    ),
    _p(
        "inference_openai_api_key",
        CATEGORY_INFERENCE,
        is_secret=True,
        label="OpenAI API key",
        relevant_when=(("inference_provider", ("openai",)),),
        help="Paste the OpenAI API key — stored encrypted and used directly. No reference needed.",
    ),
    _p(
        "inference_openai_key_ref",
        CATEGORY_INFERENCE,
        advanced=True,
        label="OpenAI key — secret reference (advanced)",
        relevant_when=(("inference_provider", ("openai",)),),
        help="Advanced: name of a key in an external secret backend (Docker secret/env). Leave "
        "blank if you entered the key above.",
    ),
    _p(
        "inference_anthropic_url",
        CATEGORY_INFERENCE,
        label="Anthropic endpoint URL",
        relevant_when=(("inference_provider", ("anthropic",)),),
        help="Anthropic Messages API base URL.",
    ),
    _p(
        "inference_anthropic_api_key",
        CATEGORY_INFERENCE,
        is_secret=True,
        label="Anthropic API key",
        relevant_when=(("inference_provider", ("anthropic",)),),
        help="Paste the Anthropic API key — stored encrypted and used directly (no reference).",
    ),
    _p(
        "inference_anthropic_key_ref",
        CATEGORY_INFERENCE,
        advanced=True,
        label="Anthropic key — secret reference (advanced)",
        relevant_when=(("inference_provider", ("anthropic",)),),
        help="Advanced: name of a key in an external secret backend (Docker secret/env). Leave "
        "blank if you entered the key above.",
    ),
    _p(
        "inference_anthropic_version",
        CATEGORY_INFERENCE,
        label="Anthropic API version",
        relevant_when=(("inference_provider", ("anthropic",)),),
        help="Anthropic API version header.",
    ),
    # --- Organize (live gate; apply still rides remediation gates) ---
    _p("organize_enabled", CATEGORY_ORGANIZE, help="Master gate for content-aware Organize."),
    _p(
        "organize_model",
        CATEGORY_ORGANIZE,
        advanced=True,
        label="Organize model (override)",
        help="Blank = use the Inference model. Only set to run Organize on a different model.",
    ),
    # --- AI concierge (live gate) ---
    _p("concierge_enabled", CATEGORY_CONCIERGE, help="Master gate for the concierge Q&A."),
    _p(
        "concierge_model",
        CATEGORY_CONCIERGE,
        advanced=True,
        label="Concierge model (override)",
        help="Blank = use the Inference model. Only set to run the concierge on a different model.",
    ),
    _p("concierge_context_max_rows", CATEGORY_CONCIERGE, help="Max rows fed to narration."),
    _p(
        "concierge_embeddings_enabled",
        CATEGORY_CONCIERGE,
        restart_required=True,
        help="Build/maintain semantic embeddings (the worker is provisioned at startup).",
    ),
    _p(
        "concierge_embedding_provider",
        CATEGORY_CONCIERGE,
        restart_required=True,
        label="Embedding provider",
        # Options track the chat provider (see _EMBED_PROVIDERS): Anthropic→voyage/ollama,
        # OpenAI→openai/ollama, Ollama→ollama. Cloud needs egress + a key.
        relevant_when=(("concierge_embeddings_enabled", (True,)),),
        help="Embedder, matched to your chat provider. Cloud embedders need egress + a key.",
    ),
    _p(
        "concierge_embedding_model",
        CATEGORY_CONCIERGE,
        restart_required=True,
        relevant_when=(("concierge_embeddings_enabled", (True,)),),
        help="Embedding model (must match the column dimension; a change is a reindex).",
    ),
    _p(
        "concierge_embedding_url",
        CATEGORY_CONCIERGE,
        restart_required=True,
        label="Embedding endpoint URL",
        relevant_when=(("concierge_embeddings_enabled", (True,)),),
        help="Embedder endpoint override (defaults per provider).",
    ),
    _p(
        "concierge_embedding_api_key",
        CATEGORY_CONCIERGE,
        is_secret=True,
        restart_required=True,
        label="Embedding API key",
        relevant_when=(
            ("concierge_embeddings_enabled", (True,)),
            ("concierge_embedding_provider", ("voyage", "openai")),
        ),
        help="Paste the cloud embedder's API key — stored encrypted and used directly.",
    ),
    _p(
        "concierge_embedding_key_ref",
        CATEGORY_CONCIERGE,
        advanced=True,
        restart_required=True,
        label="Embedding key — secret reference (advanced)",
        relevant_when=(
            ("concierge_embeddings_enabled", (True,)),
            ("concierge_embedding_provider", ("voyage", "openai")),
        ),
        help="Advanced: name of a key in an external secret backend. Leave blank if you entered "
        "the key above.",
    ),
    # --- Remediation (gate live; execute runtime provisioned at startup) ---
    _p(
        "remediation_enabled",
        CATEGORY_REMEDIATION,
        restart_required=True,
        help="Master write gate. Build/dry-run is live; the execute runtime is bound at startup.",
    ),
    _p("remediation_blast_cap", CATEGORY_REMEDIATION, help="Max items an EXECUTE may touch."),
    # --- Preview (runtime provisioned at startup; per-render caps live) ---
    _p(
        "preview_enabled",
        CATEGORY_PREVIEW,
        restart_required=True,
        help="Master gate. The sandbox runtime is provisioned at startup.",
    ),
    _p("preview_timeout_seconds", CATEGORY_PREVIEW, help="Per-render wall-clock cap (live)."),
    _p("preview_max_pages", CATEGORY_PREVIEW, help="Per-render page cap (live)."),
    _p("preview_max_input_bytes", CATEGORY_PREVIEW, help="Largest raw input for a render."),
    # --- Scan concurrency coordinator (live) ---
    _p("scan_coordinator_enabled", CATEGORY_SCAN, help="Defer overlapping heavy scans."),
    _p(
        "scan_coordinator_max_concurrent_heavy",
        CATEGORY_SCAN,
        help="Heavy scans allowed to hold a lease at once.",
    ),
    _p("scan_coordinator_heavy_entries", CATEGORY_SCAN, help="Entries above which a scan = heavy."),
    _p("scan_coordinator_lease_ttl_seconds", CATEGORY_SCAN, help="Lease crash-safety TTL (s)."),
    _p(
        "scan_coordinator_retry_after_seconds",
        CATEGORY_SCAN,
        help="Advised retry delay for a deferred scan.",
    ),
    # --- Notification Center (live) ---
    _p("notifications_enabled", CATEGORY_NOTIFICATIONS, help="Master gate for bell + channels."),
    _p(
        "notification_retention_days",
        CATEGORY_NOTIFICATIONS,
        help="Retention for read/delivered notifications.",
    ),
    # Outbound channels (ADR-039) — all live (read per dispatch). The password/webhook VALUE is a
    # named secret (added under Secrets); the *_ref settings below just name it.
    _p(
        "notify_outbound_categories",
        CATEGORY_NOTIFICATIONS,
        help="Categories that fan out to Email/Chat (the bell gets all).",
    ),
    _p(
        "notify_min_severity",
        CATEGORY_NOTIFICATIONS,
        options=("info", "warning", "critical"),
        help="Minimum severity that fans out to channels.",
    ),
    _p(
        "notify_send_timeout_seconds",
        CATEGORY_NOTIFICATIONS,
        help="Per-send timeout for an outbound channel.",
    ),
    _p(
        "notify_email_enabled",
        CATEGORY_NOTIFICATIONS,
        label="Email channel",
        help="Enable the Email (SMTP) channel.",
    ),
    _p(
        "notify_email_smtp_host",
        CATEGORY_NOTIFICATIONS,
        label="SMTP host",
        relevant_when=(("notify_email_enabled", (True,)),),
        help="SMTP server host.",
    ),
    _p(
        "notify_email_smtp_port",
        CATEGORY_NOTIFICATIONS,
        label="SMTP port",
        relevant_when=(("notify_email_enabled", (True,)),),
        help="SMTP port (587 = STARTTLS).",
    ),
    _p(
        "notify_email_use_tls",
        CATEGORY_NOTIFICATIONS,
        label="SMTP STARTTLS",
        relevant_when=(("notify_email_enabled", (True,)),),
        help="Use STARTTLS after connecting.",
    ),
    _p(
        "notify_email_username",
        CATEGORY_NOTIFICATIONS,
        label="SMTP username",
        relevant_when=(("notify_email_enabled", (True,)),),
        help="SMTP username (optional).",
    ),
    _p(
        "notify_email_password_ref",
        CATEGORY_NOTIFICATIONS,
        label="SMTP password (secret reference)",
        relevant_when=(("notify_email_enabled", (True,)),),
        help="Secret reference for the SMTP password (add the value under Secrets).",
    ),
    _p(
        "notify_email_from",
        CATEGORY_NOTIFICATIONS,
        label="Email from address",
        relevant_when=(("notify_email_enabled", (True,)),),
        help="From address.",
    ),
    _p(
        "notify_email_to",
        CATEGORY_NOTIFICATIONS,
        label="Email recipients",
        relevant_when=(("notify_email_enabled", (True,)),),
        help="Recipient address(es).",
    ),
    _p(
        "notify_chat_enabled",
        CATEGORY_NOTIFICATIONS,
        label="Chat channel",
        help="Enable the Chat channel.",
    ),
    _p(
        "notify_chat_kind",
        CATEGORY_NOTIFICATIONS,
        label="Chat kind",
        options=("discord", "slack", "telegram"),
        relevant_when=(("notify_chat_enabled", (True,)),),
        help="Chat service to post to.",
    ),
    _p(
        "notify_chat_webhook_ref",
        CATEGORY_NOTIFICATIONS,
        label="Chat webhook / token (secret reference)",
        relevant_when=(("notify_chat_enabled", (True,)),),
        help="Secret reference for the webhook URL / bot token (add the value under Secrets).",
    ),
    _p(
        "notify_chat_telegram_chat_id",
        CATEGORY_NOTIFICATIONS,
        label="Telegram chat id",
        relevant_when=(
            ("notify_chat_enabled", (True,)),
            ("notify_chat_kind", ("telegram",)),
        ),
        help="Telegram destination chat id (telegram only).",
    ),
    # Proactive watch (ADR-040) — all live (the worker re-reads effective settings each tick).
    _p(
        "watch_enabled",
        CATEGORY_NOTIFICATIONS,
        help="Proactively watch capacity + days-to-full and post alerts to the bell (live toggle).",
    ),
    _p(
        "watch_interval_seconds",
        CATEGORY_NOTIFICATIONS,
        help="How often the watcher re-assesses the estate (seconds).",
    ),
    _p(
        "watch_capacity_warn_percent",
        CATEGORY_NOTIFICATIONS,
        help="Volume fullness (%) that raises a warning capacity alert.",
    ),
    _p(
        "watch_capacity_critical_percent",
        CATEGORY_NOTIFICATIONS,
        help="Volume fullness (%) that raises a critical capacity alert.",
    ),
    _p(
        "watch_days_to_full_warn",
        CATEGORY_NOTIFICATIONS,
        help="Raise an alert when a volume is forecast to fill within this many days.",
    ),
    # --- Change-feed retention (worker provisioned at startup) ---
    _p(
        "change_log_retention_enabled",
        CATEGORY_RETENTION,
        restart_required=True,
        help="Run the change-log pruner (the worker is provisioned at startup).",
    ),
    _p("change_log_retention_days", CATEGORY_RETENTION, help="Churn retention window (days)."),
)

SETTING_POLICIES: dict[str, SettingPolicy] = {p.key: p for p in _POLICY_LIST}


@dataclass(frozen=True)
class SettingView:
    """One setting for the read surface — its policy, the effective value, and provenance."""

    key: str
    category: str
    type: str
    editable: bool
    is_secret: bool
    restart_required: bool
    help: str
    overridden: bool  # an in-app override is set (vs the env/default value)
    value: Any  # the effective value; None + is_secret means "set but masked", or "unset"
    is_set: bool  # for a secret: whether a value exists at all (masked either way)
    label: str  # human label ('Inference Provider'), the key shown secondary in the UI
    options: list[str] | None  # closed value set → render a strict dropdown
    suggestions: list[str] | None  # open value set → render a free-text combobox (datalist hints)
    relevant: bool  # whether this setting currently applies (given other settings' values)
    relevant_hint: (
        str | None
    )  # why it's inapplicable, e.g. "Applies when Inference provider is anthropic"
    advanced: bool  # tuck behind an "Advanced" disclosure in the UI


# --- Provider-dependent choices (the model + embedder pickers track the selected provider) -----
# Curated chat models per CLOUD provider — rendered as a strict dropdown (closed set). The Anthropic
# IDs are the current ones (cheapest → most capable); keep them in sync at each model launch.
_CHAT_MODELS: dict[str, tuple[str, ...]] = {
    "anthropic": ("claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-8", "claude-fable-5"),
    "openai": ("gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1"),
}
# Ollama can run ANY pulled model, so it gets a free-text combobox with a couple preferred tags
# (suggestions, not a closed set).
_OLLAMA_CHAT_SUGGESTIONS: tuple[str, ...] = ("llama3.2:3b", "llama3.1:8b")


def _default_model_for(provider: str) -> str | None:
    """The default chat model for a provider — the cheapest curated cloud model, or the safe local
    Ollama default. Used to reset the cohesive ``inference_model`` when the provider switches so a
    model from the old provider (e.g. an Ollama tag on Anthropic) can't linger and 404."""
    p = provider.lower()
    if p in _CHAT_MODELS:
        return _CHAT_MODELS[p][0]
    if p == "ollama":
        return _OLLAMA_CHAT_SUGGESTIONS[0]
    return None
# Which embedders make sense for each chat provider (ADR-035 addendum): Voyage is Anthropic's
# recommended embedder (Anthropic has no embeddings API); OpenAI users get OpenAI; local Ollama is
# always an option. Constrains the embedding-provider dropdown to the cohesive choices.
_EMBED_PROVIDERS: dict[str, tuple[str, ...]] = {
    "anthropic": ("voyage", "ollama"),
    "openai": ("openai", "ollama"),
    "ollama": ("ollama",),
}
# Suggested embedding models per embedder (free-text combobox — the model must match the column
# dimension, so it stays open rather than a closed dropdown).
_EMBED_MODELS: dict[str, tuple[str, ...]] = {
    "ollama": ("nomic-embed-text", "mxbai-embed-large"),
    "voyage": ("voyage-3.5", "voyage-3.5-lite", "voyage-3-large"),
    "openai": ("text-embedding-3-small", "text-embedding-3-large"),
}


def _choices(
    policy: SettingPolicy, effective: dict[str, Any]
) -> tuple[list[str] | None, list[str] | None]:
    """Resolve (options, suggestions) for a setting — provider-dependent for the model/embedder
    pickers, else the policy's static ``options``. ``options`` is a strict dropdown; ``suggestions``
    is a free-text combobox. At most one is non-None.
    """
    provider = str(effective.get("inference_provider", "ollama"))
    key = policy.key
    if key == "inference_model":
        # The single, cohesive chat model: strict dropdown for a cloud provider; free-text + a
        # couple preferred tags for Ollama (which can run anything).
        if provider in _CHAT_MODELS:
            return list(_CHAT_MODELS[provider]), None
        return None, list(_OLLAMA_CHAT_SUGGESTIONS)
    if key in ("organize_model", "concierge_model"):
        # Per-feature OVERRIDES: always a combobox (blank = use the Inference model), with the
        # provider's models offered as suggestions.
        return None, list(_CHAT_MODELS.get(provider, _OLLAMA_CHAT_SUGGESTIONS))
    if key == "concierge_embedding_provider":
        return list(_EMBED_PROVIDERS.get(provider, ("ollama",))), None
    if key == "concierge_embedding_model":
        embedder = str(effective.get("concierge_embedding_provider", "ollama"))
        return None, list(_EMBED_MODELS.get(embedder, ()))
    return (list(policy.options) if policy.options else None), None


def _relevance(policy: SettingPolicy, effective: dict[str, Any]) -> tuple[bool, str | None]:
    """Is ``policy`` relevant given the effective settings? Return (relevant, hint-when-not)."""
    if not policy.relevant_when:
        return True, None
    unmet: list[str] = []
    relevant = True
    for dep_key, allowed in policy.relevant_when:
        if effective.get(dep_key) not in allowed:
            relevant = False
        shown = " or ".join(str(a) for a in allowed)
        unmet.append(f"{humanize(dep_key)} is {shown}")
    return relevant, ("Applies when " + " and ".join(unmet) + ".")


def _field_type_name(key: str) -> str:
    """A short, stable type label for the UI (best-effort from the pydantic annotation)."""
    field = Settings.model_fields.get(key)
    if field is None:
        return "unknown"
    ann = field.annotation
    text = str(ann)
    if "bool" in text:
        return "bool"
    if "int" in text:
        return "int"
    if "float" in text:
        return "float"
    if "tuple" in text or "list" in text:
        return "list"
    return "str"


def _looks_like_raw_secret(value: str) -> bool:
    """Heuristic: does this look like a pasted API key rather than a reference *name*?

    A ``*_key_ref`` field holds the NAME the secret backend resolves (ADR-010) — a short label
    like ``ANTHROPIC_KEY``. Users routinely paste the key itself instead, which then (a) can't
    resolve and (b) lands UNENCRYPTED in a non-secret field. Catch the obvious cases: the common
    LLM key prefixes (Anthropic ``sk-ant-``, OpenAI ``sk-``/``sk-proj-``) and any long opaque
    token (a real reference name is short and has no business being 64+ characters).
    """
    v = value.strip()
    if v.startswith(("sk-", "sk_")):
        return True
    return len(v) >= 64 and " " not in v


@dataclass
class _Override:
    """A decoded override held in memory: the value to overlay (secrets already decrypted)."""

    value: Any
    is_secret: bool


class SettingsStoreError(Exception):
    """A settings-store operation was rejected (unknown/non-editable key, validation, or crypto)."""


class RuntimeSettingsStore:
    """Holds in-app setting overrides + named secrets; builds the effective, validated Settings.

    The store is created at startup, loaded from the DB (:meth:`refresh`), and installed on
    ``app.state`` so the request path reads :meth:`effective`. Writes go through
    :meth:`set_override`/:meth:`clear_override`, which validate, persist, bump the version, and
    refresh in-process.
    """

    def __init__(self, *, fernet: Fernet | None) -> None:
        self._fernet = fernet
        self._overrides: dict[str, _Override] = {}
        self._version = -1
        self._cache: tuple[int, int, Settings] | None = None
        # Keys we've already warned about as undecodable, so the per-tick refresh doesn't spam.
        self._warned_undecodable: set[str] = set()

    # --- key material -------------------------------------------------------------------

    @classmethod
    def from_key_material(cls, key_material: str | None) -> RuntimeSettingsStore:
        """Build a store from a urlsafe-base64 Fernet key, or an ephemeral one when ``None``.

        Mirrors the preview cache (ADR-014): production injects the key by reference (ADR-010) so
        encrypted secrets survive a restart; dev/test gets a per-process key (secrets still
        encrypted at rest, just not durable across a restart — acceptable when no secret is set).
        """
        if key_material:
            fernet = Fernet(key_material.encode("ascii"))
        else:
            fernet = Fernet(Fernet.generate_key())
        return cls(fernet=fernet)

    # --- effective settings -------------------------------------------------------------

    @property
    def version(self) -> int:
        """The loaded override-set version (monotonic; -1 before the first refresh)."""
        return self._version

    def effective(self, base: Settings) -> Settings:
        """Return the effective settings: ``base`` with field overrides overlaid + re-validated.

        Cached by ``(id(base), version)`` so the common path is a dict lookup. When ``base`` is
        replaced (e.g. a test swaps ``app.state.settings``) the identity changes and the overlay is
        rebuilt on the new base — overrides always win over whatever the current base provides.
        """
        cache = self._cache
        if cache is not None and cache[0] == id(base) and cache[1] == self._version:
            return cache[2]
        field_overrides = {
            k: o.value for k, o in self._overrides.items() if k in Settings.model_fields
        }
        if not field_overrides:
            effective = base
        else:
            merged = base.model_dump(mode="json")
            merged.update(field_overrides)
            # model_validate re-runs every field validator/constraint without re-reading the
            # environment, so an out-of-range override that slipped in can never produce an
            # invalid Settings (it would raise here and we surface the base instead).
            try:
                effective = Settings.model_validate(merged)
            except Exception:  # pragma: no cover - guarded by set-time validation
                effective = base
        self._cache = (id(base), self._version, effective)
        return effective

    # --- secret resolution (the secret-provider chain) ----------------------------------

    def resolve_secret(self, ref: str) -> str | None:
        """Return a decrypted secret stored in-app under ``ref``, or ``None`` if not set here.

        Consulted *before* the env/Docker provider (:func:`build_secret_provider`) so an operator
        can supply a credential in the UI instead of the host environment.
        """
        entry = self._overrides.get(ref)
        if entry is None or not entry.is_secret:
            return None
        value = entry.value
        return value if isinstance(value, str) else None

    # --- load / persist -----------------------------------------------------------------

    async def refresh(self, session: AsyncSession) -> None:
        """(Re)load all overrides + the version from the DB, decoding/decrypting each row.

        Fault-tolerant: a missing table (a non-schema test DB) or a row that fails to decode/decrypt
        is treated as "no override" so the store degrades to the env base rather than failing the
        app. A bad row is skipped, not fatal.
        """
        try:
            rows = (await session.execute(select(SettingsOverride))).scalars().all()
            version = (
                await session.execute(
                    select(SettingsVersion.version).where(SettingsVersion.id == SETTINGS_VERSION_ID)
                )
            ).scalar()
        except SQLAlchemyError:
            # No settings tables yet (or a transient DB error): keep the env base, no overrides.
            self._overrides = {}
            self._version = 0
            self._cache = None
            return
        decoded: dict[str, _Override] = {}
        for row in rows:
            try:
                if row.is_secret:
                    plain = self._decrypt(row.value)
                    decoded[row.key] = _Override(value=plain, is_secret=True)
                else:
                    decoded[row.key] = _Override(value=json.loads(row.value), is_secret=False)
                # Decodes fine now → allow a fresh warning if it ever fails again.
                self._warned_undecodable.discard(row.key)
            except Exception:  # a row we can't decode (ephemeral-key secret after a
                # restart, or a corrupt value) is intentionally skipped, not fatal: the store
                # degrades to the env base for that key rather than failing the whole app.
                # Log it (no value) so a "my secret vanished after a restart" is diagnosable — the
                # usual cause is no persistent settings_store_key_ref (an ephemeral key). Once per
                # key per process so the 15s refresh loop doesn't spam the log.
                if row.key not in self._warned_undecodable:
                    self._warned_undecodable.add(row.key)
                    _log.warning(
                        "skipping undecodable setting override — likely encrypted with a prior "
                        "ephemeral key (set FATHOM_SETTINGS_STORE_KEY_REF for durable secrets)",
                        extra={"setting_key": row.key, "is_secret": bool(row.is_secret)},
                    )
                continue
        self._overrides = decoded
        self._version = int(version or 0)
        self._cache = None

    async def set_override(
        self,
        session: AsyncSession,
        *,
        base: Settings,
        key: str,
        value: Any,
        updated_by: str | None,
    ) -> None:
        """Validate + persist an override (encrypting secrets), bump the version, and refresh.

        Raises :class:`SettingsStoreError` for an unknown/non-editable key or a value that fails the
        pydantic field constraints (so an invalid override is never stored).
        """
        policy = SETTING_POLICIES.get(key)
        if policy is None or not policy.editable:
            # A free-form named secret (not a Settings field) is allowed only via set_secret.
            raise SettingsStoreError(f"{key!r} is not an editable setting")
        # Guard the secret-reference fields against a pasted key: a ``*_key_ref`` value is a NAME
        # the secret backend resolves (ADR-010), never the key itself. Rejecting it here stops the
        # key silently landing unencrypted in a non-secret field (and never resolving).
        if key.endswith("_key_ref") and isinstance(value, str) and _looks_like_raw_secret(value):
            label = policy.label or humanize(key)
            raise SettingsStoreError(
                f"{label} expects a secret-backend reference NAME, not the key itself — this "
                "value looks like a raw API key. Store the key under Named secrets, then put its "
                "reference name here (ADR-010)."
            )
        if key in Settings.model_fields:
            self._validate_field(base, key, value)
        # Cohesion: capture the pre-change provider so a genuine provider SWITCH (not a no-op
        # re-save) can reset the shared inference_model to the new provider's default below.
        old_provider = (
            self.effective(base).inference_provider if key == "inference_provider" else None
        )
        if policy.is_secret:
            stored = self._encrypt(json.dumps(value) if not isinstance(value, str) else value)
        else:
            stored = json.dumps(value)
        await self._upsert(
            session, key=key, value=stored, is_secret=policy.is_secret, by=updated_by
        )
        # Switching the chat provider resets the cohesive inference_model to that provider's default
        # in the same transaction, so a model from the old provider can't linger (the runtime guard
        # is the backstop; this keeps the stored/displayed value coherent). Per-feature overrides
        # (organize_model/concierge_model) are explicit opt-ins and left untouched — the UI banner
        # tells the operator to change those separately if wanted.
        if (
            key == "inference_provider"
            and isinstance(value, str)
            and value.lower() != (old_provider or "").lower()
        ):
            default_model = _default_model_for(value)
            if default_model is not None:
                await self._upsert(
                    session,
                    key="inference_model",
                    value=json.dumps(default_model),
                    is_secret=False,
                    by=updated_by,
                )
        await self._bump_version(session)
        await self.refresh(session)

    async def set_secret(
        self,
        session: AsyncSession,
        *,
        ref: str,
        value: str,
        updated_by: str | None,
    ) -> None:
        """Store a free-form named secret (a secret-backend reference value), encrypted at rest.

        Unlike :meth:`set_override` this is for credentials the secret provider resolves by name
        (e.g. ``inference_anthropic_key_ref`` points here). It never overlays into Settings.
        """
        if not ref or len(ref) > 128:
            raise SettingsStoreError("secret reference must be 1..128 chars")
        if ref in Settings.model_fields:
            raise SettingsStoreError(f"{ref!r} is a setting; use the setting endpoint")
        stored = self._encrypt(value)
        await self._upsert(session, key=ref, value=stored, is_secret=True, by=updated_by)
        await self._bump_version(session)
        await self.refresh(session)

    async def clear_override(self, session: AsyncSession, *, key: str) -> bool:
        """Delete an override (reset to the env default), bump the version, refresh. Returns hit."""
        result = cast(
            CursorResult[object],
            await session.execute(delete(SettingsOverride).where(SettingsOverride.key == key)),
        )
        deleted = result.rowcount or 0
        await self._bump_version(session)
        await self.refresh(session)
        return bool(deleted)

    def reveal(self, key: str) -> str:
        """Return the decrypted secret for ``key`` (admin-only, step-up-gated at the route)."""
        entry = self._overrides.get(key)
        if entry is None or not entry.is_secret:
            raise SettingsStoreError(f"{key!r} is not a stored secret")
        if not isinstance(entry.value, str):
            raise SettingsStoreError(f"{key!r} did not decrypt to a string")
        return entry.value

    # --- read surface -------------------------------------------------------------------

    def list_settings(self, base: Settings) -> list[SettingView]:
        """Build the read surface: every policied setting with its effective value (secrets masked).

        Free-form named secrets (not Settings fields) are returned separately by
        :meth:`list_named_secrets` (names only — never values).
        """
        effective = self.effective(base)
        eff_dump = effective.model_dump(mode="json")
        views: list[SettingView] = []
        for policy in _POLICY_LIST:
            overridden = policy.key in self._overrides
            relevant, hint = _relevance(policy, eff_dump)
            options, suggestions = _choices(policy, eff_dump)
            views.append(
                SettingView(
                    key=policy.key,
                    category=policy.category,
                    type=_field_type_name(policy.key),
                    editable=policy.editable,
                    is_secret=policy.is_secret,
                    restart_required=policy.restart_required,
                    help=policy.help,
                    overridden=overridden,
                    # A secret's value is never exposed in the list; non-secrets show the value.
                    value=None if policy.is_secret else eff_dump.get(policy.key),
                    is_set=(overridden or bool(eff_dump.get(policy.key)))
                    if policy.is_secret
                    else True,
                    label=policy.label or humanize(policy.key),
                    options=options,
                    suggestions=suggestions,
                    relevant=relevant,
                    relevant_hint=hint,
                    advanced=policy.advanced,
                )
            )
        return views

    def list_named_secrets(self) -> list[str]:
        """Return the names of free-form secrets stored in-app (not Settings fields)."""
        return sorted(
            k for k, o in self._overrides.items() if o.is_secret and k not in Settings.model_fields
        )

    # --- internals ----------------------------------------------------------------------

    def _validate_field(self, base: Settings, key: str, value: Any) -> None:
        merged = base.model_dump(mode="json")
        merged[key] = value
        try:
            Settings.model_validate(merged)
        except Exception as exc:  # pydantic ValidationError (or coercion failure)
            raise SettingsStoreError(f"invalid value for {key!r}: {exc}") from exc

    def _encrypt(self, plaintext: str) -> str:
        assert self._fernet is not None  # noqa: S101 — always built in from_key_material
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def _decrypt(self, ciphertext: str) -> str:
        assert self._fernet is not None  # noqa: S101
        return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")

    async def _upsert(
        self, session: AsyncSession, *, key: str, value: str, is_secret: bool, by: str | None
    ) -> None:
        existing = await session.get(SettingsOverride, key)
        if existing is None:
            session.add(SettingsOverride(key=key, value=value, is_secret=is_secret, updated_by=by))
        else:
            existing.value = value
            existing.is_secret = is_secret
            existing.updated_by = by

    async def _bump_version(self, session: AsyncSession) -> None:
        row = await session.get(SettingsVersion, SETTINGS_VERSION_ID)
        if row is None:
            session.add(SettingsVersion(id=SETTINGS_VERSION_ID, version=1))
        else:
            await session.execute(
                update(SettingsVersion)
                .where(SettingsVersion.id == SETTINGS_VERSION_ID)
                .values(version=SettingsVersion.version + 1)
            )


def build_secret_provider(
    store: RuntimeSettingsStore | None,
    fallback: Callable[[str], str],
) -> Callable[[str], str]:
    """Compose the in-app secret store in front of ``fallback`` (env/Docker; ADR-010).

    Returns a ``ref -> value`` provider that returns an in-app secret when one is stored under
    ``ref``, else delegates to ``fallback``. With no store it is just ``fallback`` (unchanged
    behaviour), so callers can always wire this without a feature flag.
    """
    if store is None:
        return fallback

    def provider(ref: str) -> str:
        value = store.resolve_secret(ref)
        if value is not None:
            return value
        return fallback(ref)

    return provider
