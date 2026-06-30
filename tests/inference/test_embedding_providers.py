"""Embedding provider tests (ADR-035 addendum) — each backend + the egress-gated factory.

Providers are unit-tested against a stubbed httpx (no live model). The factory must default to local
Ollama, refuse a cloud embedder without egress / a key, and resolve the key by reference (ADR-010).
"""

from __future__ import annotations

import httpx
import pytest

from fathom.core.settings import Settings
from fathom.inference import InferenceError
from fathom.inference.embeddings import (
    INPUT_DOCUMENT,
    INPUT_QUERY,
    OllamaEmbedder,
    OpenAIEmbedder,
    VoyageEmbedder,
    build_embedding_provider,
)


def _patch_post(monkeypatch: pytest.MonkeyPatch, response: httpx.Response | Exception) -> dict:
    seen: dict[str, object] = {}

    async def fake_post(self: httpx.AsyncClient, url: str, **kw: object) -> httpx.Response:
        seen["url"] = url
        seen["json"] = kw.get("json")
        seen["headers"] = kw.get("headers")
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    return seen


async def test_ollama_embeds(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _patch_post(monkeypatch, httpx.Response(200, json={"embeddings": [[0.1, 0.2]]}))
    out = await OllamaEmbedder(base_url="http://x:11434", model="m", timeout_seconds=5).embed(
        ["hello"], input_type=INPUT_DOCUMENT
    )
    assert out == [[0.1, 0.2]]
    assert str(seen["url"]).endswith("/api/embed")


async def test_ollama_count_mismatch_is_502(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_post(monkeypatch, httpx.Response(200, json={"embeddings": [[0.1]]}))
    with pytest.raises(InferenceError) as exc:
        await OllamaEmbedder(base_url="http://x", model="m", timeout_seconds=5).embed(
            ["a", "b"], input_type=INPUT_DOCUMENT
        )
    assert exc.value.status_code == 502


async def test_voyage_sends_input_type_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _patch_post(
        monkeypatch, httpx.Response(200, json={"data": [{"embedding": [0.3, 0.4]}]})
    )
    out = await VoyageEmbedder(
        base_url="https://api.voyageai.com", model="voyage-4-lite", api_key="k", timeout_seconds=5
    ).embed(["q"], input_type=INPUT_QUERY)
    assert out == [[0.3, 0.4]]
    assert str(seen["url"]).endswith("/v1/embeddings")
    assert seen["json"]["input_type"] == "query"  # type: ignore[index]
    assert seen["headers"]["Authorization"] == "Bearer k"  # type: ignore[index]


async def test_openai_embeds(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_post(monkeypatch, httpx.Response(200, json={"data": [{"embedding": [0.5]}]}))
    out = await OpenAIEmbedder(
        base_url="https://api.openai.com/v1", model="m", api_key="k", timeout_seconds=5
    ).embed(["x"], input_type=INPUT_DOCUMENT)
    assert out == [[0.5]]


async def test_timeout_is_504(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_post(monkeypatch, httpx.TimeoutException("slow"))
    with pytest.raises(InferenceError) as exc:
        await OllamaEmbedder(base_url="http://x", model="m", timeout_seconds=1).embed(
            ["a"], input_type=INPUT_DOCUMENT
        )
    assert exc.value.status_code == 504


def test_factory_defaults_to_ollama() -> None:
    provider = build_embedding_provider(Settings())
    assert isinstance(provider, OllamaEmbedder)


def test_factory_cloud_refused_without_egress() -> None:
    s = Settings(concierge_embedding_provider="voyage", inference_allow_egress=False)
    with pytest.raises(InferenceError) as exc:
        build_embedding_provider(s)
    assert exc.value.status_code == 503


def test_factory_cloud_needs_key_reference() -> None:
    s = Settings(concierge_embedding_provider="voyage", inference_allow_egress=True)
    with pytest.raises(InferenceError):
        build_embedding_provider(s)  # no key ref configured


def test_factory_resolves_key_by_reference() -> None:
    s = Settings(
        concierge_embedding_provider="voyage",
        inference_allow_egress=True,
        concierge_embedding_key_ref="VOYAGE_KEY",
        concierge_embedding_model="voyage-4-lite",
    )
    provider = build_embedding_provider(s, secret_provider=lambda ref: f"secret-for-{ref}")
    assert isinstance(provider, VoyageEmbedder)


def test_factory_unknown_provider_raises() -> None:
    with pytest.raises(InferenceError):
        build_embedding_provider(Settings(concierge_embedding_provider="bogus"))
