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
