# ADR-038 — Runtime settings store: in-app, persistent, encrypted, live-reload configuration

**Status:** Accepted  **Date:** 2026-06-19  **Deciders:** project owner

## Context

Fathom's configuration is env-seeded: a `pydantic-settings` `Settings(BaseSettings)` reads `FATHOM_*`
environment variables once at process start and is then immutable. That is the right default for
infrastructure (it is declarative, reproducible, and keeps secrets out of the app — ADR-010), but it
makes the day-to-day operator experience heavy: every knob change — flip the concierge on, point at a
different Ollama, raise a cap, add an API key — means editing a compose file / secret and restarting
the API. The owner wanted the opposite ergonomics for the common case: *"pull all the settings into
the application so that if a user wants to set the bare minimum to get up and running then the rest
can be set without restarting the app — settings need to be persistent and encrypted, and we need
RBAC controls."*

Three decisions were taken up front:

1. **In-app value wins; env seeds the default.** An override set in the UI takes precedence over the
   environment; the environment only provides the starting value.
2. **Secrets encrypted at rest, admins can reveal.** Secret values (API keys, channel
   webhooks/passwords, the ingest proxy secret) are stored Fernet-encrypted; an admin can reveal the
   plaintext through an explicit, gated path.
3. **A new `MANAGE_SETTINGS` capability, admin-only, with secrets extra-gated.** Managing settings is
   an admin power; revealing or setting a *secret* additionally requires fresh step-up MFA.

## Decision

A **runtime settings store** that overlays persisted overrides on the env-seeded `Settings` and
re-validates the result through the same pydantic model. The effective settings are read on the
request path, so a change is live on the **next request** — no restart.

**Data model** (`settings_override` + `settings_version`, one Alembic migration, portable
PG+SQLite). One row per override: `key`, `value` (JSON for a non-secret; Fernet ciphertext for a
secret), `is_secret`, `updated_at`, `updated_by`. `settings_version` is a single-row monotonic
counter bumped on every mutation so other workers can cheaply detect a change and reload.

**Effective settings.** `RuntimeSettingsStore.effective(base)` overlays the field overrides on
`base.model_dump()` and calls `Settings.model_validate(...)` — which runs every field validator and
constraint **without re-reading the environment**, so an out-of-range override can never produce an
invalid `Settings`. The result is cached by `(id(base), version)`; the common path is a dict lookup.
The store is installed on `app.state`; `deps.request_settings` returns `store.effective(base)` so
**all** request-path consumers (every feature gate, model name, URL, cap, threshold) pick up overrides
uniformly through the existing `SettingsDep` seam — no consumer changes.

**Secrets.** Secret values are encrypted with a Fernet key resolved by reference from the secret
backend (`settings_store_key_ref`, ADR-010) — never the key itself; an ephemeral per-process key in
dev/test (encrypted, just not durable across a restart). Two flavours: a **secret Settings field**
(e.g. `ingest_proxy_secret`) overlays decrypted into the effective settings; a **free-form named
secret** (e.g. an `ANTHROPIC_KEY` the operator types in instead of an env var) is consulted by
`build_secret_provider`, which composes the store **in front of** the env/Docker provider so a
credential set in the UI resolves by reference exactly like an env secret. This is what lets an
operator get the cloud concierge running without touching the host environment.

**Live reload, honestly.** Two tiers, both recorded in the per-setting policy
(`SETTING_POLICIES`): a setting read per request/tick is **live**; a setting whose effect is bound at
startup (a provisioned worker/runtime — preview, the embedding worker, the remediation execute
runtime — or the DB engine) is flagged `restart_required` so the API/UI tell the operator the
override persisted but needs a restart for full effect. A `SettingsRefreshWorker` re-reads the DB on
an interval so a change made by one worker converges across workers without a restart.

**RBAC.** A new `MANAGE_SETTINGS` capability, conferred **only** by the admin role (it falls out of
`_ADMIN = frozenset(Capability)` automatically). Read + non-secret edit need just the capability;
**reveal a secret** and **set/clear a named secret** additionally require `require_step_up_mfa`
(fresh MFA) — the same posture as the deployment and remediation surfaces. Secrets are masked in the
list (`value: null`) and only the explicit `POST /settings/{key}/reveal` returns plaintext.

**Surface.** `GET /api/v1/settings` (list with policy + effective values, secrets masked),
`PUT /api/v1/settings/{key}` (set, validated), `DELETE /api/v1/settings/{key}` (reset to default),
`PUT /api/v1/settings/secrets` + `DELETE /api/v1/settings/secrets/{ref}` (named secrets, +MFA),
`POST /api/v1/settings/{key}/reveal` (+MFA). A Settings SPA page groups by category, edits values,
reveals secrets, resets overrides, and badges `restart_required`.

## Consequences

- **Bare-minimum-to-running** is now an in-app flow: an admin can enable the concierge, point it at a
  provider, and paste the API key — all live, all encrypted — without editing the host environment.
- **The trust boundary is preserved.** The destructive *write* gates (remediation execute, deploy)
  are unchanged: this store can flip `remediation_enabled` (a per-request gate) but the execute
  runtime is still provisioned only at startup (`restart_required`), so a browser flip can never
  silently arm file mutation. Secrets never leave masked except through the MFA-gated reveal.
- **ADR-010 still holds for infra secrets.** The encryption key and deep infra references stay
  env/secret-backend managed; the store is an *additional, operator-convenience* secret source that
  sits in front of — never replaces — the env/Docker provider.
- **Allow-list, not a blanket dump.** Only settings with an explicit policy are editable; everything
  else stays env-only and is not exposed for writing (the read-only `/config` view is unchanged).
- **Validation is centralised.** Because every write re-validates through `Settings`, the store can
  never persist a value the process couldn't have booted with.
- **Migration:** one portable migration adds the two tables off the ai-suite merge head; with no rows
  the effective settings are exactly the env base (behaviour-preserving).

## 2026-06-20 addendum — richer policy metadata (labels, dropdowns, relevance)

The settings panel was made "intelligent" per the owner: each `SettingPolicy` now carries an optional
**`label`** (human name; the API falls back to a humanised key — `inference_provider` → "Inference
provider"), an optional **`options`** tuple (a closed value set → the UI renders a **dropdown**, e.g.
the inference provider, embedder, chat kind, min-severity), and a **`relevant_when`** gate (tuples of
`(other_key, allowed_values)`). The store computes each setting's `relevant` flag + a
`relevant_hint` from the *effective* values and returns them on `SettingOut`. The UI shows the label
prominently with the env key secondary, and **disables** (greys, with the hint) any setting that
doesn't currently apply — e.g. the Anthropic settings are disabled while the provider is `ollama`,
and the email/chat/telegram fields disable until their channel/kind is selected. Pure additive
metadata; no schema/migration change, and validation/secrets/relevance stay server-authoritative.

## 2026-06-21 addendum — direct API-key entry (no reference indirection)

The original model required the operator to (1) store a *named secret* (ref name + value), (2)
remember the name, then (3) type that name into a `*_key_ref` setting — clunky, and a footgun:
pasting the key straight into the *reference* field left it **unencrypted** in a non-secret override
and the provider 500'd trying to resolve a secret literally named `sk-ant-…`.

Fix — make the common case "paste the key, done":
- **Direct secret settings.** Added `inference_anthropic_api_key`, `inference_openai_api_key`,
  `concierge_embedding_api_key` as **secret settings** (`is_secret=True`). The UI renders them as
  masked fields; saving stores the value **encrypted at rest** (same path as `ingest_proxy_secret`)
  and it overlays decrypted into effective settings — used directly, no resolution step.
- **References demoted to advanced.** The `*_key_ref` fields stay (for external secret backends —
  Docker secrets / env, the ADR-010 path) but are flagged `advanced=True` and collapse behind an
  "Advanced" disclosure in the UI. A new `SettingPolicy.advanced` flows through `SettingView` →
  `SettingOut`.
- **Resolution prefers direct.** `resolve_api_key(direct, ref, resolve_secret)` returns the direct
  key if set, else resolves the reference. Used by `build_inference_provider` (openai/anthropic) and
  `build_embedding_provider` (voyage/openai). The egress gate (ADR-022) is unchanged.
- **Guard retained.** `set_override` still rejects a raw key pasted into a `*_key_ref` field (sk-/sk_
  prefix or any 64+ char opaque token), pointing the operator at the direct key field.

Other `*_key_ref` settings are intentionally **left as references**: the store's own Fernet key
(`settings_store_key_ref`, bootstrap chicken-and-egg), and the generated PEM signing/CA keys
(remediation dispatch, preview/browse grants, deploy CA) — none are user-pasted vendor tokens.
Additive only; no schema/migration change.

## 2026-06-21 addendum — durable encryption key required for in-app secrets

Discovered in the field: with `settings_store_key_ref` unset, `from_key_material(None)` mints an
**ephemeral per-process Fernet key**, so every in-app secret (the direct API keys above, named
secrets, encrypted settings) becomes **undecryptable after a restart** — `refresh()` silently skips
the unreadable row and the field reverts to its env default. Symptom: "I saved my API key, then it
stopped working after a redeploy."

Hardening:
- **Document + provision a stable key.** `FATHOM_SETTINGS_STORE_KEY_REF` (+ the referenced env/Docker
  secret) is now in the quickstart `.env.example` and compose; production must set it.
- **Loud startup warning** when no persistent key is configured (app.py).
- **`refresh()` logs** each skipped/undecodable override (key name only) instead of silently
  dropping it — so the cause is diagnosable.
- **Graceful resolution** — `resolve_api_key` treats an unresolvable reference as "no key" so the
  caller raises a clean `InferenceError` (actionable message) instead of an opaque 500.

Rotating the key invalidates previously-stored ciphertext (re-enter secrets once); that's inherent
to changing an encryption key, not a regression.

## 2026-06-23 addendum — provider-aware pickers + hide-not-disable

The owner reviewed the LLM-inference settings and asked for the model/embedder pickers to track the
selected provider, and for irrelevant settings to **disappear** rather than grey out. Three changes,
all additive to the policy metadata (no schema/migration):

**1. `suggestions` — an open-set combobox alongside the closed-set `options`.** `options` renders a
**strict dropdown** (must pick a listed value); the new `suggestions` field renders a **free-text
combobox** (`<input list>` + `<datalist>`) — a value is offered but anything is allowed. `SettingView`
/ `SettingOut` carry both; at most one is non-null per setting.

**2. Provider-dependent choices.** The store resolves options/suggestions from the *effective*
settings (`_choices`), not statically:
- `inference_model` → a **strict dropdown** of the current models for a cloud provider (Anthropic:
  `claude-haiku-4-5` / `sonnet-4-6` / `opus-4-8` / `fable-5`; OpenAI: the gpt-4o family) and a
  **combobox** with preferred tags (`llama3.2:3b`, `llama3.1:8b`) for Ollama, which can run anything.
- `organize_model` / `concierge_model` (the per-feature overrides, [ADR-022](ADR-022-pluggable-inference-provider.md))
  → comboboxes seeded with the provider's models, blank = use the inference model.
- `concierge_embedding_provider` → options **track the chat provider** (Anthropic→`voyage`/`ollama`,
  OpenAI→`openai`/`ollama`, Ollama→`ollama`), making the [ADR-035](ADR-035-ai-concierge.md) embedder
  mapping (Voyage is Anthropic's recommended embedder) a UI constraint; embedding-model suggestions
  per embedder.
- New `relevant_when` gates: the **Ollama URL** applies only for the Ollama provider, the **cloud
  egress** gate only for openai/anthropic.

**3. Hide, not disable** (revises the *2026-06-20 addendum*). The UI now **omits** any setting with
`relevant=false` entirely instead of greying it with a hint — so a provider's page shows only the
fields that apply (e.g. selecting Anthropic hides the Ollama URL and all OpenAI fields). The server
contract (`relevant` + `relevant_hint` on `SettingOut`) is unchanged; only the client's treatment of
`relevant=false` flipped from *disable* to *hide*. A strict dropdown still keeps the **current**
value selectable even when it falls outside the closed set, so an env-seeded model (e.g. the default
`llama3.2:3b` while the provider is Anthropic) is never silently dropped.
