# ADR-022: Pluggable LLM inference provider, local-first

**Status:** Accepted **Date:** 2026-06-07 **Deciders:** project owner

## Context

The Organize subsystem (ADR-021) needs an LLM to turn file digests into a proposed structure.
Fathom is self-hosted and no-egress-by-default (doc 10 — data sovereignty); shipping a hard
dependency on a cloud API (the prior art's default is Groq) would send content-derived text off
the operator's hosts on every run. But a cloud model is sometimes wanted (no local GPU, better
quality). This mirrors choices Fathom has already made pluggable: `StorageBackend` (ADR-004),
`PlatformAdapter` (ADR-008), the secret backend (ADR-010), the preview `FileFetcher` (ADR-016).

## Decision

Introduce an **`InferenceProvider`** protocol (structural typing, like the other Fathom plugin
points) with one job: take a structured prompt and return a **validated structured response**
(JSON-schema-constrained), no streaming, no tool-use, no chat history.

- **`OllamaProvider` is the default** — talks to a local Ollama server (`/api/chat` with
  `format: <json-schema>`), so inference stays **on the operator's own hosts** ("incognito" by
  construction). The base URL + model are config (`FATHOM_INFERENCE_OLLAMA_URL`,
  `FATHOM_ORGANIZE_MODEL`, default `llama3.2:3b`).
- **`OpenAICompatibleProvider`** (OpenAI / Groq / any OpenAI-compatible endpoint) is **opt-in**:
  it refuses to construct unless a separate **egress gate** is explicitly enabled
  (`FATHOM_INFERENCE_ALLOW_EGRESS=true`), and the API key is a **reference into the secret backend**
  (ADR-010), never embedded. Every cloud call is audited as a data-egress event.
- The provider is selected by `FATHOM_INFERENCE_PROVIDER` (`ollama` | `openai`), default `ollama`.
- Responses are **always parsed against a Pydantic schema** at the boundary; a malformed / refused
  model response is a typed error, never raw text reaching business logic. A hard request timeout
  + bounded output size cap the blast radius of a slow or runaway model.

The provider knows nothing about Organize — it is a thin, reusable inference seam, so a future
classifier / summariser can use the same plug.

## Consequences

### Positive
- Sovereignty by default: the local Ollama path keeps all content-derived text on-host; a cloud
  model is a deliberate, gated, audited opt-in — not the path of least resistance.
- One small seam (provider protocol) isolates a fast-moving dependency (model APIs) from the rest
  of the code; swapping providers/models is config, not a rewrite.
- Schema-validated output means the planner consumes typed data, not free-form text — robust to
  model quirks and a smaller injection surface.

### Negative
- Two providers + the egress gate to test and document; the local path needs an Ollama deployment
  and enough RAM/GPU for a small model.
- Structured-output support varies by model; the planner must degrade gracefully when a model
  ignores the schema (retry / reject, never act on garbage).

### Risks
- **Accidental egress** (cloud provider selected without intent) → mitigated by the explicit,
  separate egress gate + audit; default is local.
- **Secret leakage** → the cloud key is by-reference (ADR-010), never logged, never in the digest.
- **Model unavailability** (Ollama down) → a typed provider error surfaces a clean "inference
  unavailable" to the UI; the read-only suggest path fails closed and changes nothing.

## 2026-06-23 addendum — Anthropic provider + one cohesive inference model

Two refinements as the inference seam grew a second consumer (the AI concierge, ADR-035) and a
third provider:

**1. Anthropic Messages API provider.** Added `AnthropicProvider` alongside Ollama/OpenAI, selected
by `FATHOM_INFERENCE_PROVIDER=anthropic`. Structured output is obtained via a **forced single-tool
call** (the JSON schema becomes the tool `input_schema`), then re-validated against the Pydantic
schema like every other provider. It rides the same egress gate, and its key is either direct
(`inference_anthropic_api_key`, the ADR-038 direct-key path) or by reference. Embeddings are
configured **separately** (`concierge_embedding_provider`, ADR-035) — Claude has no embeddings API,
so an Anthropic chat estate pairs with the Voyage embedder.

**2. One cohesive chat model across all AI features.** The original design gave each feature its own
model id (`FATHOM_ORGANIZE_MODEL`, later a separate concierge model) — easy to leave inconsistent.
Collapsed to a single **`inference_model`** (`FATHOM_INFERENCE_MODEL`, default `llama3.2:3b`) that
Organize **and** Concierge both request from the configured provider. `build_inference_provider`
now defaults `model or inference_model`. The old `organize_model` / `concierge_model` become
**optional per-feature overrides** (`str | None`, default `None` → "use the inference model"); a
feature resolves `<override> or inference_model`. Backward-compatible: a deployment that still pins
`FATHOM_ORGANIZE_MODEL` keeps that as a winning override, and the new default equals the old one, so
behaviour is unchanged until the operator opts into a different cohesive model. The Settings UI
surfaces `inference_model` as the primary picker and the two overrides under "Advanced"
(see [ADR-038 addendum](ADR-038-runtime-settings-store.md)).

## 2026-06-29 addendum — provider/model continuity guard

The "one cohesive `inference_model`" above is a single field shared across providers, but a model id
only means something to the provider it belongs to. Selecting a cloud provider while `inference_model`
still holds the previous provider's model — most often an Ollama tag like `llama3.2:3b` carried over
after switching `inference_provider` to `anthropic` (model and provider are independent per-row
settings, and the picker deliberately preserves the current value rather than dropping it) — would
call the cloud API with an unknown model and 404. This is the operator's exact concern: *select
Anthropic, it must use Anthropic, not the Ollama model.*

`build_inference_provider` now coerces a stale/empty model to the cloud provider's default at the
single seam every chat feature (Organize, Concierge) uses — so it holds for the UI, env, and API
entry paths alike:

- **Anthropic:** an empty model, or one containing `:` (an Ollama `name:tag`; no Anthropic id has a
  colon) → falls back to `claude-haiku-4-5` (cheapest curated), with a warning. A genuine `claude-*`
  id — including one outside the curated picker set — passes through unchanged.
- **OpenAI:** only an *empty* model falls back (`gpt-4o-mini`). A `:`-bearing id is preserved: a
  self-hosted OpenAI-compatible endpoint (vLLM, Ollama's `/v1` shim) legitimately uses such ids.
- **Ollama:** untouched — its model is free-form and `name:tag` is normal.

This is a runtime safety net, not a settings rewrite: the stored `inference_model` is unchanged (a
provider-aware *reset-on-switch* in the Settings UI remains a possible follow-up for display
coherence). **Embeddings are deliberately not coerced** — `concierge_embedding_model` is bound to the
vector column width (`concierge_embedding_dim`: nomic 768 vs Voyage 1024), so silently swapping it
would mint wrong-dimension vectors; a mismatched embedder instead degrades gracefully to substring
search (ADR-035).
