"""Suitability / traffic-light engine (ADR-037) — can this host run a given AI option?

Pure logic mapping a host's hardware facts (CPU / RAM / GPU) — and, when known, the estate size
that drives the semantic-index RAM — to a ✅/⚠️/❌ rating per AI option plus one "best for you"
recommendation (chat provider + model, embedder + dimension). It sends nothing off-host and touches
no DB; the API layer gathers the facts and renders the result. Shared by the onboarding wizard and
the concierge's model picker (ADR-035 addendum) so they agree.

Thresholds come from the cost/model research (``docs/research/concierge-inference-cost-analysis``):
the binding homelab constraint is **RAM** — both to hold a local chat model and to hold the vector
index — with a GPU's VRAM the big accelerator for the chat model.
"""

from __future__ import annotations

from dataclasses import dataclass

# Ratings (stable identifiers; the UI maps to colours/labels).
RATING_GREEN = "green"  # fits comfortably
RATING_AMBER = "amber"  # works, but slow or with caveats
RATING_RED = "red"  # won't fit / not recommended

_GIB = 1024**3

# Recommended model identifiers (kept in step with the Settings defaults + the cost research).
_LOCAL_SMALL = "llama3.2:3b"  # ~3-4 GB resident; the safe local default
_LOCAL_LARGE = "llama3.1:8b"  # ~8 GB; wants a GPU or a lot of RAM
_CLOUD_CHAT = "claude-haiku-4-5"  # any hardware; needs egress + a key
_LOCAL_EMBED = "nomic-embed-text"  # 768-dim, local
_VOYAGE_EMBED = "voyage-4-lite"  # 1024-dim, Anthropic's preferred embedder (egress)
_LOCAL_EMBED_DIM = 768
_VOYAGE_EMBED_DIM = 1024

# Rough per-vector index cost at 768 dims with int8 storage + HNSW overhead (~1 KiB/vector). The
# index must fit comfortably in RAM alongside everything else, so we budget against a RAM fraction.
_BYTES_PER_VECTOR = 1024


@dataclass(frozen=True)
class HostFacts:
    """Hardware facts an agent reports (all optional — a pre-facts agent reports nothing)."""

    cpu_cores: int | None = None
    cpu_model: str | None = None
    ram_bytes: int | None = None
    gpu_name: str | None = None
    gpu_vram_bytes: int | None = None
    arch: str | None = None

    @property
    def known(self) -> bool:
        """True when at least RAM is known — enough to assess the binding constraint."""
        return self.ram_bytes is not None


@dataclass(frozen=True)
class OptionAssessment:
    """One AI option's traffic-light rating + a one-line human reason."""

    key: str
    label: str
    rating: str
    reason: str


@dataclass(frozen=True)
class SuitabilityResult:
    """A host's full assessment + the recommended concrete settings."""

    facts_known: bool
    options: list[OptionAssessment]
    recommendation: str
    recommended_chat_provider: str  # ollama | anthropic | none
    recommended_chat_model: str | None
    recommended_embedder: str  # ollama | voyage | none
    recommended_embedding_dim: int | None


def _gb(n: int | None) -> str:
    return "unknown" if n is None else f"{n / _GIB:.0f} GB"


def _assess_local_small(ram: int, vram: int) -> OptionAssessment:
    if vram >= 4 * _GIB or ram >= 8 * _GIB:
        rating, reason = RATING_GREEN, "fits a small (3B) local model comfortably"
    elif ram >= 4 * _GIB:
        rating, reason = RATING_AMBER, "runs a small model on CPU — usable but slow"
    else:
        rating, reason = RATING_RED, "not enough RAM for a local model (needs ~4 GB free)"
    return OptionAssessment("local_chat_small", "Local chat — small model (3B)", rating, reason)


def _assess_local_large(ram: int, vram: int) -> OptionAssessment:
    if vram >= 16 * _GIB:
        rating, reason = RATING_GREEN, "GPU VRAM fits an 8B+ model"
    elif vram >= 10 * _GIB or ram >= 32 * _GIB:
        rating, reason = RATING_AMBER, "an 8B model will run but slowly (CPU or partial offload)"
    else:
        rating, reason = RATING_RED, "not enough VRAM/RAM for a large local model"
    return OptionAssessment("local_chat_large", "Local chat — large model (8B+)", rating, reason)


def _assess_cloud_chat() -> OptionAssessment:
    return OptionAssessment(
        "cloud_chat",
        "Cloud chat (Anthropic/OpenAI)",
        RATING_GREEN,
        "runs on any hardware — requires egress + an API key; prompts leave the host",
    )


def _assess_embeddings(ram: int, estate_entry_count: int | None) -> OptionAssessment:
    if estate_entry_count is not None:
        index_bytes = estate_entry_count * _BYTES_PER_VECTOR
        if index_bytes <= ram * 0.25:
            rating = RATING_GREEN
            reason = f"~{_gb(index_bytes)} vector index fits well in {_gb(ram)} RAM"
        elif index_bytes <= ram * 0.5:
            rating = RATING_AMBER
            reason = f"~{_gb(index_bytes)} index is large for {_gb(ram)} RAM — scope what you embed"
        else:
            rating = RATING_RED
            reason = f"~{_gb(index_bytes)} index won't fit {_gb(ram)} RAM — embed only key volumes"
    elif ram >= 16 * _GIB:
        rating, reason = RATING_GREEN, "ample RAM for a scoped semantic index"
    elif ram >= 8 * _GIB:
        rating = RATING_AMBER
        reason = "embed only data volumes; the vector index grows with the number of files"
    else:
        rating, reason = RATING_RED, "limited RAM — semantic search may not fit; use substring find"
    return OptionAssessment("semantic_embeddings", "Semantic search (embeddings)", rating, reason)


def _recommend(
    small: OptionAssessment,
    large: OptionAssessment,
    embeddings: OptionAssessment,
    *,
    egress_allowed: bool,
) -> tuple[str, str, str, str, int | None]:
    # Chat: prefer the best green local tier; else cloud if egress is on; else the least-bad local.
    if large.rating == RATING_GREEN:
        chat_provider, chat_model, chat_text = "ollama", _LOCAL_LARGE, "an 8B local model"
    elif small.rating == RATING_GREEN:
        chat_provider, chat_model, chat_text = "ollama", _LOCAL_SMALL, "a small (3B) local model"
    elif egress_allowed:
        chat_provider, chat_model, chat_text = "anthropic", _CLOUD_CHAT, "the cloud (Claude Haiku)"
    elif small.rating == RATING_AMBER:
        chat_provider, chat_model, chat_text = "ollama", _LOCAL_SMALL, "a small local model (slow)"
    else:
        chat_provider, chat_model, chat_text = "anthropic", _CLOUD_CHAT, "the cloud (enable egress)"
    # Embedder: local if it fits; else Voyage when egress is on; else local scoped.
    if embeddings.rating == RATING_GREEN:
        embedder, dim, embed_text = "ollama", _LOCAL_EMBED_DIM, "local embeddings"
    elif egress_allowed:
        embedder, dim, embed_text = "voyage", _VOYAGE_EMBED_DIM, "Voyage embeddings (cloud)"
    else:
        embedder, dim, embed_text = "ollama", _LOCAL_EMBED_DIM, "local embeddings (scoped)"
    text = f"Use {chat_text} for chat and {embed_text} for semantic search."
    return chat_provider, chat_model, text, embedder, dim


def assess(
    facts: HostFacts,
    *,
    estate_entry_count: int | None = None,
    egress_allowed: bool = False,
) -> SuitabilityResult:
    """Assess every AI option for ``facts`` and pick a recommendation (pure; no I/O)."""
    if not facts.known:
        unknown = "hardware not reported yet — deploy/upgrade the agent to probe it"
        opts = [
            OptionAssessment(
                "local_chat_small", "Local chat — small model (3B)", RATING_AMBER, unknown
            ),
            OptionAssessment(
                "local_chat_large", "Local chat — large model (8B+)", RATING_AMBER, unknown
            ),
            _assess_cloud_chat(),
            OptionAssessment(
                "semantic_embeddings", "Semantic search (embeddings)", RATING_AMBER, unknown
            ),
        ]
        return SuitabilityResult(
            facts_known=False,
            options=opts,
            recommendation="Deploy or upgrade the agent so it can report this host's hardware.",
            recommended_chat_provider="anthropic" if egress_allowed else "ollama",
            recommended_chat_model=_CLOUD_CHAT if egress_allowed else _LOCAL_SMALL,
            recommended_embedder="voyage" if egress_allowed else "ollama",
            recommended_embedding_dim=_VOYAGE_EMBED_DIM if egress_allowed else _LOCAL_EMBED_DIM,
        )
    ram = facts.ram_bytes or 0
    vram = facts.gpu_vram_bytes or 0
    small = _assess_local_small(ram, vram)
    large = _assess_local_large(ram, vram)
    cloud = _assess_cloud_chat()
    embeddings = _assess_embeddings(ram, estate_entry_count)
    provider, model, text, embedder, dim = _recommend(
        small, large, embeddings, egress_allowed=egress_allowed
    )
    return SuitabilityResult(
        facts_known=True,
        options=[small, large, cloud, embeddings],
        recommendation=text,
        recommended_chat_provider=provider,
        recommended_chat_model=model,
        recommended_embedder=embedder,
        recommended_embedding_dim=dim,
    )
