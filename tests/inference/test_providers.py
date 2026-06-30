"""Inference provider tests (ADR-022) — schema validation, failure mapping, the egress gate.

The providers are unit-tested against a stubbed httpx (no live model in the gate). A separate,
opt-in integration test runs against a real local Ollama when one is reachable.
"""

from __future__ import annotations

import httpx
import pytest
from pydantic import BaseModel

from fathom.core.settings import Settings
from fathom.inference import (
    AnthropicProvider,
    InferenceError,
    OllamaProvider,
    OpenAICompatibleProvider,
    build_inference_provider,
)


class _Out(BaseModel):
    folder: str


def _patch_post(monkeypatch: pytest.MonkeyPatch, response: httpx.Response | Exception) -> None:
    async def fake_post(self: httpx.AsyncClient, url: str, **kw: object) -> httpx.Response:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)


def _ollama() -> OllamaProvider:
    return OllamaProvider(base_url="http://x:11434", model="m", timeout_seconds=5)


async def test_ollama_returns_validated_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_post(
        monkeypatch, httpx.Response(200, json={"message": {"content": '{"folder":"Docs"}'}})
    )
    out = await _ollama().complete(system="s", user="u", schema=_Out)
    assert isinstance(out, _Out)
    assert out.folder == "Docs"


async def test_ollama_timeout_is_504(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_post(monkeypatch, httpx.TimeoutException("slow"))
    with pytest.raises(InferenceError) as exc:
        await _ollama().complete(system="s", user="u", schema=_Out)
    assert exc.value.status_code == 504


async def test_ollama_unreachable_is_503(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_post(monkeypatch, httpx.ConnectError("down"))
    with pytest.raises(InferenceError) as exc:
        await _ollama().complete(system="s", user="u", schema=_Out)
    assert exc.value.status_code == 503


async def test_ollama_output_off_schema_is_502(monkeypatch: pytest.MonkeyPatch) -> None:
    # The model answered, but not with the requested shape → validation failure (never raw text).
    _patch_post(monkeypatch, httpx.Response(200, json={"message": {"content": '{"nope":1}'}}))
    with pytest.raises(InferenceError) as exc:
        await _ollama().complete(system="s", user="u", schema=_Out)
    assert exc.value.status_code == 502


async def test_ollama_non_200_is_503(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_post(monkeypatch, httpx.Response(500, text="boom"))
    with pytest.raises(InferenceError):
        await _ollama().complete(system="s", user="u", schema=_Out)


async def test_openai_parses_choices(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"choices": [{"message": {"content": '{"folder":"Cloud"}'}}]}
    _patch_post(monkeypatch, httpx.Response(200, json=body))
    prov = OpenAICompatibleProvider(
        base_url="http://x/v1", model="m", api_key="k", timeout_seconds=5
    )
    out = await prov.complete(system="s", user="u", schema=_Out)
    assert out.folder == "Cloud"


# --- Anthropic provider (ADR-022 cloud path) --------------------------------------------


def _anthropic() -> AnthropicProvider:
    return AnthropicProvider(base_url="http://x", model="m", api_key="k", timeout_seconds=5)


async def test_anthropic_returns_validated_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    # Structured output arrives as a forced tool_use block's ``input`` object (not raw text).
    body = {"content": [{"type": "tool_use", "name": "emit_result", "input": {"folder": "Docs"}}]}
    _patch_post(monkeypatch, httpx.Response(200, json=body))
    out = await _anthropic().complete(system="s", user="u", schema=_Out)
    assert out.folder == "Docs"


async def test_anthropic_timeout_is_504(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_post(monkeypatch, httpx.TimeoutException("slow"))
    with pytest.raises(InferenceError) as exc:
        await _anthropic().complete(system="s", user="u", schema=_Out)
    assert exc.value.status_code == 504


async def test_anthropic_unreachable_is_503(monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-timeout transport failure (connection refused/reset) maps to 503 "unreachable", the
    # broader httpx.HTTPError branch distinct from the timeout 504 above.
    _patch_post(monkeypatch, httpx.ConnectError("connection refused"))
    with pytest.raises(InferenceError) as exc:
        await _anthropic().complete(system="s", user="u", schema=_Out)
    assert exc.value.status_code == 503


async def test_anthropic_no_tool_use_block_is_502(monkeypatch: pytest.MonkeyPatch) -> None:
    # The model answered with prose instead of calling the tool → malformed, never returned raw.
    body = {"content": [{"type": "text", "text": "I refuse"}]}
    _patch_post(monkeypatch, httpx.Response(200, json=body))
    with pytest.raises(InferenceError) as exc:
        await _anthropic().complete(system="s", user="u", schema=_Out)
    assert exc.value.status_code == 502


async def test_anthropic_output_off_schema_is_502(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"content": [{"type": "tool_use", "name": "emit_result", "input": {"nope": 1}}]}
    _patch_post(monkeypatch, httpx.Response(200, json=body))
    with pytest.raises(InferenceError) as exc:
        await _anthropic().complete(system="s", user="u", schema=_Out)
    assert exc.value.status_code == 502


# --- factory + egress gate (ADR-022) ----------------------------------------------------


def test_factory_default_is_ollama() -> None:
    prov = build_inference_provider(Settings())
    assert isinstance(prov, OllamaProvider)


def test_factory_cloud_refused_without_egress_gate() -> None:
    # provider=openai but egress not allowed → fail closed (no off-host call is even constructed).
    s = Settings(inference_provider="openai", inference_allow_egress=False)
    with pytest.raises(InferenceError) as exc:
        build_inference_provider(s)
    assert exc.value.status_code == 503


def test_factory_cloud_needs_key_reference() -> None:
    s = Settings(
        inference_provider="openai", inference_allow_egress=True, inference_openai_key_ref=None
    )
    with pytest.raises(InferenceError):
        build_inference_provider(s)


def test_factory_cloud_resolves_key_by_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FATHOM_TEST_INFER_KEY", "sk-secret")
    s = Settings(
        inference_provider="openai",
        inference_allow_egress=True,
        inference_openai_key_ref="FATHOM_TEST_INFER_KEY",
    )
    prov = build_inference_provider(s)
    assert isinstance(prov, OpenAICompatibleProvider)


def test_factory_unknown_provider() -> None:
    with pytest.raises(InferenceError):
        build_inference_provider(Settings(inference_provider="myllm"))


def test_factory_anthropic_refused_without_egress_gate() -> None:
    s = Settings(inference_provider="anthropic", inference_allow_egress=False)
    with pytest.raises(InferenceError) as exc:
        build_inference_provider(s)
    assert exc.value.status_code == 503


def test_factory_anthropic_needs_key_reference() -> None:
    s = Settings(
        inference_provider="anthropic",
        inference_allow_egress=True,
        inference_anthropic_key_ref=None,
    )
    with pytest.raises(InferenceError):
        build_inference_provider(s)


def test_factory_anthropic_resolves_key_by_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FATHOM_TEST_ANTHROPIC_KEY", "sk-ant-secret")
    s = Settings(
        inference_provider="anthropic",
        inference_allow_egress=True,
        inference_anthropic_key_ref="FATHOM_TEST_ANTHROPIC_KEY",
    )
    prov = build_inference_provider(s)
    assert isinstance(prov, AnthropicProvider)


# --- provider/model continuity: a cloud provider must never run an Ollama model (ADR-022) --------


def _anthropic_settings(model: str) -> Settings:
    return Settings(
        inference_provider="anthropic",
        inference_model=model,
        inference_allow_egress=True,
        inference_anthropic_api_key="sk-ant-direct",
    )


def test_anthropic_coerces_stale_ollama_model_to_default() -> None:
    # The exact continuity bug: inference_model is shared across providers, so an Ollama tag left
    # over from before the provider switch would 404 the Anthropic API. Selecting Anthropic must use
    # a real Anthropic model, never the Ollama one.
    prov = build_inference_provider(_anthropic_settings("llama3.2:3b"))
    assert isinstance(prov, AnthropicProvider)
    assert prov._model == "claude-haiku-4-5"


def test_anthropic_coerces_empty_model_to_default() -> None:
    prov = build_inference_provider(_anthropic_settings(""))
    assert prov._model == "claude-haiku-4-5"


def test_anthropic_keeps_a_real_claude_model() -> None:
    # A genuine Anthropic model id (including one outside the curated picker set) is passed through.
    prov = build_inference_provider(_anthropic_settings("claude-opus-4-8"))
    assert prov._model == "claude-opus-4-8"


def test_anthropic_coerces_a_per_feature_model_override() -> None:
    # organize/concierge pass model=organize_model|concierge_model into the factory; a stale Ollama
    # override is coerced the same way as the global inference_model.
    prov = build_inference_provider(_anthropic_settings("claude-sonnet-4-6"), model="llama3.1:8b")
    assert prov._model == "claude-haiku-4-5"


def test_openai_keeps_colon_model_for_compat_endpoints() -> None:
    # OpenAI-compatible endpoints (vLLM, Ollama's /v1 shim) legitimately use name:tag ids, so a ':'
    # model is preserved for the openai provider — only Anthropic treats ':' as a stale Ollama tag.
    s = Settings(
        inference_provider="openai",
        inference_model="llama3.1:8b",
        inference_allow_egress=True,
        inference_openai_api_key="sk-openai-direct",
    )
    prov = build_inference_provider(s)
    assert isinstance(prov, OpenAICompatibleProvider)
    assert prov._model == "llama3.1:8b"


def test_openai_coerces_empty_model_to_default() -> None:
    s = Settings(
        inference_provider="openai",
        inference_model="",
        inference_allow_egress=True,
        inference_openai_api_key="sk-openai-direct",
    )
    prov = build_inference_provider(s)
    assert prov._model == "gpt-4o-mini"


def test_ollama_keeps_its_model_untouched() -> None:
    # The local provider is unaffected: its model is free-form and ':' tags are normal.
    s = Settings(inference_provider="ollama", inference_model="llama3.1:8b")
    prov = build_inference_provider(s)
    assert isinstance(prov, OllamaProvider)
    assert prov._model == "llama3.1:8b"


def test_resolve_api_key_prefers_direct_and_tolerates_bad_ref() -> None:
    from fathom.inference import resolve_api_key

    def boom(ref: str) -> str:
        raise RuntimeError("secret backend down")

    # Direct key wins and the (failing) ref is never consulted.
    assert resolve_api_key("direct-key", "REF", boom) == "direct-key"
    # An unresolvable ref degrades to None (clean "no key") rather than raising → no opaque 500.
    assert resolve_api_key(None, "REF", boom) is None
    assert resolve_api_key(None, None, boom) is None


def test_factory_uses_direct_anthropic_api_key() -> None:
    # The easy path: paste the key (stored as an encrypted secret setting) — no reference needed.
    s = Settings(
        inference_provider="anthropic",
        inference_allow_egress=True,
        inference_anthropic_api_key="sk-ant-direct",
    )
    assert isinstance(build_inference_provider(s), AnthropicProvider)


def test_factory_uses_direct_openai_api_key() -> None:
    s = Settings(
        inference_provider="openai",
        inference_allow_egress=True,
        inference_openai_api_key="sk-openai-direct",
    )
    assert isinstance(build_inference_provider(s), OpenAICompatibleProvider)


def test_factory_direct_key_preferred_over_reference() -> None:
    # Direct key wins; an unresolvable ref alongside it is never consulted, so the build succeeds.
    s = Settings(
        inference_provider="anthropic",
        inference_allow_egress=True,
        inference_anthropic_api_key="sk-ant-direct",
        inference_anthropic_key_ref="NOPE_UNRESOLVABLE_REF",
    )
    assert isinstance(build_inference_provider(s), AnthropicProvider)


def test_factory_uses_one_inference_model_by_default() -> None:
    # Cohesion: with no per-feature override, every feature gets the single inference_model.
    prov = build_inference_provider(Settings(inference_model="cohesive-model"))
    assert isinstance(prov, OllamaProvider)
    assert prov._model == "cohesive-model"


def test_factory_per_feature_override_beats_inference_model() -> None:
    prov = build_inference_provider(Settings(inference_model="base"), model="override")
    assert isinstance(prov, OllamaProvider)
    assert prov._model == "override"


def test_factory_model_override() -> None:
    # The concierge passes its own model; the factory honours the override for the chosen provider.
    prov = build_inference_provider(Settings(), model="concierge-model")
    assert isinstance(prov, OllamaProvider)
    assert prov._model == "concierge-model"


# --- opt-in live integration (skipped unless a real Ollama + model is reachable) --------


async def _ollama_live() -> bool:
    try:
        async with httpx.AsyncClient(timeout=3) as c:
            r = await c.get("http://127.0.0.1:11434/api/tags")
            return r.status_code == 200 and "llama3.2:3b" in r.text
    except httpx.HTTPError:
        return False


async def test_live_ollama_structured_output() -> None:
    if not await _ollama_live():
        pytest.skip("no local Ollama with llama3.2:3b")
    prov = OllamaProvider(
        base_url="http://127.0.0.1:11434", model="llama3.2:3b", timeout_seconds=60
    )
    out = await prov.complete(
        system="You suggest one destination folder for a file. Reply only as JSON.",
        user="File: invoice_2024_acme.pdf",
        schema=_Out,
    )
    assert out.folder  # a non-empty suggestion, schema-validated
