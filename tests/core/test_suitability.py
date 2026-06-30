"""Suitability engine tests (ADR-037) — traffic-light ratings + the recommendation.

Pure logic, no I/O: a beefy GPU box rates everything green; a small box rates local models red and
falls back to cloud (when egress is on); unknown facts degrade to amber + a "deploy the agent"
nudge; and the estate size drives the semantic-index rating when known.
"""

from __future__ import annotations

from fathom.core.suitability import (
    RATING_AMBER,
    RATING_GREEN,
    RATING_RED,
    HostFacts,
    assess,
)

_GIB = 1024**3


def _rating(result: object, key: str) -> str:
    return next(o.rating for o in result.options if o.key == key)  # type: ignore[attr-defined]


def test_gpu_workstation_is_all_green() -> None:
    facts = HostFacts(cpu_cores=16, ram_bytes=64 * _GIB, gpu_vram_bytes=16 * _GIB)
    r = assess(facts)
    assert _rating(r, "local_chat_small") == RATING_GREEN
    assert _rating(r, "local_chat_large") == RATING_GREEN
    assert r.recommended_chat_provider == "ollama"
    assert r.recommended_chat_model == "llama3.1:8b"  # the large local tier


def test_small_box_local_red_without_egress() -> None:
    facts = HostFacts(cpu_cores=2, ram_bytes=2 * _GIB)
    r = assess(facts, egress_allowed=False)
    assert _rating(r, "local_chat_small") == RATING_RED
    assert _rating(r, "local_chat_large") == RATING_RED
    # No local fit + no egress → it still recommends cloud (the only thing that can work).
    assert r.recommended_chat_provider == "anthropic"


def test_small_box_recommends_cloud_when_egress_on() -> None:
    facts = HostFacts(cpu_cores=2, ram_bytes=2 * _GIB)
    r = assess(facts, egress_allowed=True)
    assert r.recommended_chat_provider == "anthropic"
    assert r.recommended_chat_model == "claude-haiku-4-5"
    assert r.recommended_embedder == "voyage"
    assert r.recommended_embedding_dim == 1024


def test_midrange_cpu_only_is_amber_small_green_via_ram() -> None:
    facts = HostFacts(cpu_cores=8, ram_bytes=16 * _GIB)  # no GPU
    r = assess(facts)
    assert _rating(r, "local_chat_small") == RATING_GREEN  # 16 GB RAM clears the 8 GB bar
    assert _rating(r, "local_chat_large") == RATING_RED  # needs VRAM or 32 GB
    assert r.recommended_chat_model == "llama3.2:3b"


def test_cloud_chat_always_green() -> None:
    r = assess(HostFacts(ram_bytes=1 * _GIB))
    assert _rating(r, "cloud_chat") == RATING_GREEN


def test_unknown_facts_degrade_to_amber() -> None:
    r = assess(HostFacts())  # no RAM → not known
    assert r.facts_known is False
    assert _rating(r, "local_chat_small") == RATING_AMBER
    assert "agent" in r.recommendation.lower()


def test_embeddings_rating_uses_estate_size() -> None:
    facts = HostFacts(ram_bytes=8 * _GIB)
    # A tiny estate fits comfortably → green; a huge estate won't → red.
    small = assess(facts, estate_entry_count=100_000)
    big = assess(facts, estate_entry_count=50_000_000)
    assert _rating(small, "semantic_embeddings") == RATING_GREEN
    assert _rating(big, "semantic_embeddings") == RATING_RED
