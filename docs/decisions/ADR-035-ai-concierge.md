# ADR-035 — AI concierge: natural-language Q&A over the catalogue

**Status:** Accepted  **Date:** 2026-06-18  **Deciders:** project owner

## Context

Operators want to ask the estate questions in plain language instead of navigating charts and
filters: *"how full are my disks and what filesystems are they?"*, *"which non-OS folders change
most?"*, and — the headline — *"I can't find this file; when was it last seen / was it deleted?"*.
The wish was a concierge that "knows the whole fleet from memory and answers fast," running on the
**local Ollama** today but **pluggable to external vendors** (Anthropic, OpenAI) later.

Two facts shaped the design:

1. **Most of the data already exists.** Deletion/last-seen is first-class (`fs_entry.present`,
   `removed_at`, `last_seen_snapshot_id`, ADR-006). Disk space + types are on `volume` (`fs_type`,
   `pool`, `total/used/free`, `kind`). Folder churn is derivable from `change_log` +
   `subtree_rollup`/`size_history`. So this is mostly a **query + LLM-orchestration** feature, not a
   data-capture one.
2. **The LLM seam already exists** (ADR-022): an `InferenceProvider.complete(system, user, schema)`
   protocol with Ollama + OpenAI-compatible providers and an egress-gated factory; the Organize
   feature (ADR-021) is the template (model proposes structured data only; the server owns authority).

## Decision

A **tool-calling concierge over curated, scope-enforcing query functions** — *not* text-to-SQL,
*not* free-form RAG. The model has no authority: it only picks **one tool from a closed enum** plus
typed params; the server runs the matching query and decides what the principal may see.

**Loop** (on the unchanged `complete()` seam — no native tool-use added, since provider tool
dialects diverge):

1. **classify** — `complete(…, schema=ConciergeIntent)` → `{tool, params}` (closed enum).
2. **execute** — pure server dispatch to a `core/concierge/queries.py` function, passing the
   route's `ScopeFilter` (host/volume + the `Volume.kind` system-volume gate, AR-011).
3. **narrate** — `complete(…, schema=ConciergeAnswer)` fed the *already-authorised* rows → prose.
   **Citations are built server-side from the result rows**, never by the model, so a cited
   path/id can never be hallucinated. The narration prompt frames rows as **untrusted content**
   (a filename could read "ignore your instructions").

**Tools (Phase 1):** `find_file` (incl. soft-deleted + last-seen time), `fleet_storage` (per-host
space + disk types), `hot_folders` (non-OS churn ranking; `Volume.kind != 'system'`),
`growth_forecast` (linear days-to-full). `app_access` and `other` short-circuit with honest canned
answers (no narration call → nothing fabricated).

**Semantic search (Phase 2, pgvector):** an optional `semantic_search` tool for fuzzy "find by
meaning". A new `fs_entry_embedding` table stores a vector of each data-volume file's **name + path
only — never content** (`vector(768)` on PostgreSQL via pgvector, JSON on SQLite for the test
suite). An incremental, gated worker (`concierge_embeddings_enabled`, default OFF) backfills it via
local Ollama `/api/embed`. The cosine query applies the same scope gate; any failure (no pgvector,
nothing embedded yet, embed unreachable) degrades gracefully to substring find.

**Providers:** Ollama by default (local, no egress). An `AnthropicProvider` (Messages API; forced
single-tool-use for schema-constrained JSON) is added behind the **same egress gate** as the
OpenAI-compatible one — cloud is refused unless `inference_allow_egress` is set and the key resolves
by reference (ADR-010). `build_inference_provider` gains a model override so the concierge uses
`concierge_model`.

## Consequences

- **Default-OFF** behind `concierge_enabled` (a deliberate runbook flip like organize/preview);
  semantic search is behind a second gate (`concierge_embeddings_enabled`). Read-only throughout.
- **Privacy:** the default local path sends nothing off-host. With cloud egress explicitly enabled,
  the narration step sends file **names/paths** (never content) off-host — the documented trade-off.
- **"What apps access a folder" is out of scope** — there is no process/app attribution or `atime`
  in the catalogue; the concierge answers "not instrumented yet". Capturing it is a separate
  agent-side subsystem (future): sampled `/proc`/`fanotify` access → a server-re-derived
  `path_access` table + a new tool.
- **Surface (addendum below):** the embedder is being generalised the way the chat provider is.
- **Surface:** `POST /api/v1/concierge/ask` (`VIEW_METADATA` + scope), a Concierge SPA page, and the
  `concierge_*` feature flags on the read-only config view. pgvector adds a `pgvector/pgvector:pg16`
  image + one migration; plain catalogue use needs none of it.

## 2026-06-19 addendum — embedding-provider abstraction + index freshness

Cost/model research (`docs/research/concierge-inference-cost-analysis.md`) surfaced two refinements.
Both are accepted; the research doc holds the detail.

**1. Generalise the embedder the way the chat provider already is.** Today the chat provider is
pluggable (Ollama/OpenAI/Anthropic) but the embedder is hardwired to local Ollama. Add an
**`EmbeddingProvider` protocol** + `build_embedding_provider(settings)` factory with implementations
`OllamaEmbedder` (local `nomic-embed-text`, 768-dim, the default), `VoyageEmbedder` (**Anthropic's
documented/preferred embedder** — Claude has *no* embedding API; `voyage-4-lite`, 1024-dim) and
`OpenAIEmbedder` (1536-dim). Built behind the **same egress gate** as chat (cloud refused unless
`inference_allow_egress` + a key-by-reference, ADR-010). New settings:
`concierge_embedding_provider/model/dim/key_ref/url`. **Sensible defaults, not auto-detection:**
local nomic by default; default to Voyage when chat = Anthropic + egress is on. The operator commits
to one embedder **and dimension at deploy** (the dimension fixes the column — switching later is a
deliberate *reindex*). Embed catalogue rows as `document`, the query as `query` (`input_type`
asymmetry). The model **traffic-light / "best for you"** picker is shared with the onboarding
suitability engine (ADR-037) so the wizard and the concierge agree.

**2. Index freshness & RAG quality.** How the semantic index copes as the estate changes:
new files are embedded next tick (built); a rename/move makes a new row (embedded fresh) and the old
row goes `present=False`; a content edit leaves the *name* unchanged so the embedding stays valid
(we embed names, not bytes — cheap + stable). **To build:** (a) **prune stale embeddings** for
deleted (`present=False`) entries — they're filtered from results but the vectors linger; (b) drive
incremental embedding **off the `ChangeLog`** (re-embed only changed paths) instead of scanning the
whole catalogue each tick — the scale fix at 20–40M rows; (c) **hybrid retrieval** — blend the vector
search with the exact substring/structured `find_last_seen`, optionally re-ranked; (d) treat an
embedder change as a **reindex** (different vector space + dimension).

**Cost/storage note:** the **vector-index RAM** (not the API bill) is the real homelab constraint at
estate scale; the biggest lever is **scoping what you embed** (data volumes, not caches/system),
then smaller dimension (Matryoshka) or `int8` quantization. Full figures + a CPU-vs-GPU and
cold-start analysis are in the research doc.

## 2026-06-20 addendum — floating contextual sidebar (UI surface change)

The concierge moves from a nav **page** to a **floating, VS-Code-style docked sidebar** (the GUI
review and owner call). The reasoning + decisions:

- **Surface.** A bottom-right launcher icon opens a right-docked chat sidebar; it is shown **only
  when `concierge_enabled`** (server config), and is hidden entirely otherwise. On login it shows
  the icon unless the user has **pinned** it before (pin persists in `localStorage`; pinned = docked
  and reopens next login, and the main content is padded so the panel never covers it). The old
  `/concierge` route + nav item are removed; the ask/answer UI is the reusable `ConciergeChat`.
- **Contextual (soft hint).** The page the user is on is sent as `ConciergeAskRequest.page` and
  woven into the **classify** prompt as a hint, so an ambiguous question is read against the current
  view — *but* it never overrides the question: a duplicates question asked from the dashboard still
  routes to the duplicates/storage tool. Narration uses the question only.
- **Still system-scoped.** No behaviour change to the trust model: the classifier already routes
  anything off-topic (general knowledge, weather, chit-chat) to `other` and refuses it; the prompt
  was hardened to say so explicitly. Read-only throughout; the model still has no authority.

No API/data change beyond the optional `page` hint field. Recorded in full in
[ADR-043](ADR-043-frontend-ux-overhaul.md) alongside the rest of the GUI-review pass.

## 2026-06-21 addendum — more tools + conversational memory + clarify

Extending the concierge while keeping the no-authority trust model (the model still only picks ONE
closed-enum tool; the server runs the scoped query and builds citations):

- **More tools (Phase 1):** `largest` (top_n_subtrees — biggest consumers under the scoped volume),
  `reclaimable` (duplicate_summary — bytes freeable from duplicates), `forecast` (growth_forecast
  over every in-scope volume root — growth rate + days-to-full, soonest first). The chat now sends
  the currently-scoped `volume_id` so volume-targeted tools act on the active view.
- **Conversational memory (Phase 2):** the chat is a message thread holding client-side history; the
  last N (role, content) turns are sent and used **only by the classify step** to resolve follow-ups
  ("and on host 2?"). Narration still uses the current question + freshly-fetched scope-filtered
  rows, so an answer can't drift from authorised data. History is bounded (turns + chars) client- and
  server-side; it is not durably persisted server-side.
- **Clarify:** a new `clarify` tool lets classify return ONE short follow-up question when a storage
  question is too vague to route, instead of guessing — short-circuits with no narration.

- **/commands (Phase 3):** the chat recognises slash-commands. Data commands force a tool — the
  request carries an optional `tool` the server validates to the enum and runs *without* the LLM
  classify (deterministic, still scope-filtered): `/find`, `/largest`, `/forecast`, `/duplicates`,
  `/storage`, `/hot`, `/search`. Navigation/scope commands (`/go`, `/scope`, `/clear`, `/help`) run
  purely client-side.
- **Action handoff (Phase 4):** an answer may carry `actions` — NAVIGATION-ONLY suggestions the UI
  renders as buttons (e.g. reclaimable → "Review & reclaim duplicates" → /duplicates). The concierge
  never executes a mutation; these route the user to the page whose own RBAC + MFA gates the write
  (the Reclaim wizard, etc.). Read-only posture preserved end to end.

## 2026-06-23 addendum — coverage tool, no clarify-loops, conversational narration

A real chat transcript exposed three quality gaps; fixed without changing the trust model (the
model still has no authority — it picks one closed-enum tool; queries scope-filter; citations are
server-built):

- **Clarify no longer loops.** The classify step could re-ask the *same* follow-up forever — a
  user answering "yes" got the identical question back. The service now detects when our previous
  turn was itself a clarifying question (heuristic: the last assistant turn ends with `?`) and (a)
  tells the classifier the current message is the **answer** — resolve it to a real tool, pick the
  first option offered for a bare "yes" — and (b) if the model still returns `clarify`, breaks the
  loop with a capability hint instead of repeating. `clarify` is also re-scoped in the prompt to a
  genuine last resort.
- **New `coverage` tool.** There was no way to answer "what paths are collected on ctu", "which
  hosts do you know", or "is ctu being scanned" — so the model clarified endlessly. `scanned_paths()`
  lists, per in-scope host, the scanned volumes (collected paths) with indexed-file counts + last
  scan time. It also lets a zero result distinguish *nothing matches here* from *that host has no
  scanned data*, fixing answers like "no movies on ctu" that were really "ctu isn't indexed". Same
  scope + `Volume.kind` system gate; per-volume counts/last-scan resolved only for the already
  scope-authorised volume set. Surfaced as `/scanned` (alias `/coverage`).
- **Conversational, grounded narration.** The narrate prompt now leads with the direct answer,
  explains *why* a result is empty and suggests the obvious next step, and uses the conversation so
  far for pronoun/"yes" continuity — while every fact stays grounded in the freshly-fetched,
  scope-filtered data block (still treated as untrusted; no fabrication). History is fed to the
  narrate step as well as classify.

Additive; no schema/migration change. Read-only throughout.
