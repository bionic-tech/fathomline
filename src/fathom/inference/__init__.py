"""Pluggable LLM inference (ADR-022) — the seam the Organize feature (ADR-021) talks to.

``build_inference_provider(settings)`` is the factory: it returns the configured provider and is
the single place the **egress gate** is enforced — the cloud provider is constructed only when
``inference_allow_egress`` is True and its API key resolves from the secret backend (ADR-010). The
default is the local Ollama path (on-host, no egress).
"""

from __future__ import annotations

from collections.abc import Callable

from fathom.inference.anthropic import AnthropicProvider
from fathom.inference.base import InferenceError, InferenceProvider
from fathom.inference.ollama import OllamaProvider
from fathom.inference.openai import OpenAICompatibleProvider
from fathom.logging import get_logger

__all__ = [
    "AnthropicProvider",
    "InferenceError",
    "InferenceProvider",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "build_inference_provider",
    "resolve_api_key",
]

_log = get_logger("fathom.inference")

# The cohesive ``inference_model`` is one field shared across providers, but a model id only means
# something to the provider it belongs to. So a value carried over from a previous provider — most
# often an Ollama tag like ``llama3.2:3b`` after switching the provider to a cloud one — or an empty
# model would make the cloud API 404. Each cloud provider's default model (cheapest of its curated
# set; kept in step with settings_store._CHAT_MODELS) is the fallback so selecting a cloud provider
# "just works" regardless of how it was set (UI / env / API).
_CLOUD_DEFAULT_MODEL = {"anthropic": "claude-haiku-4-5", "openai": "gpt-4o-mini"}


def _cloud_model(provider: str, model: str) -> str:
    """Coerce a stale/empty chat model to the cloud provider's default; pass a real model through.

    An Ollama model tag contains ``:`` and no cloud model id does, so for **Anthropic** a ``:``
    value is an unmistakable carry-over from the local provider and is replaced. A non-empty,
    ``:``-free custom model is preserved — a self-hosted OpenAI-compatible endpoint legitimately
    uses names outside the curated set (including Ollama-style ``name:tag`` via its ``/v1`` shim),
    so for **OpenAI** only an empty model falls back. Warns whenever it substitutes.
    """
    default = _CLOUD_DEFAULT_MODEL[provider]
    stale_local_tag = provider == "anthropic" and ":" in model
    if not model or stale_local_tag:
        _log.warning(
            "inference_model %r is not valid for the %s provider; using %r — pick a %s model in "
            "Settings (the model is shared across providers and did not follow the switch)",
            model or "",
            provider,
            default,
            provider,
            extra={"provider": provider, "configured_model": model, "model": default},
        )
        return default
    return model


def resolve_api_key(
    direct: str | None,
    ref: str | None,
    resolve_secret: Callable[[str], str],
) -> str | None:
    """Resolve a provider API key, preferring a directly-entered key over a secret reference.

    ``direct`` is the key typed into the UI (stored ENCRYPTED as a secret setting — the easy path).
    ``ref`` is the legacy/advanced path: a name resolved from an external secret backend
    (Docker secret/env, ADR-010). Direct wins; the ref is the fallback for external-secret setups.
    """
    if direct:
        return direct
    if ref:
        # A reference that doesn't resolve (e.g. a name with no backing secret, or a raw key
        # mistakenly left here) must degrade to "no key" — the caller then raises a clean
        # InferenceError instead of leaking the backend's lookup error as an opaque 500.
        try:
            return resolve_secret(ref) or None
        except Exception:
            return None
    return None


def build_inference_provider(
    settings: object,
    *,
    model: str | None = None,
    secret_provider: Callable[[str], str] | None = None,
) -> InferenceProvider:
    """Build the configured :class:`InferenceProvider` from settings (fail-closed on egress).

    ``settings`` is a :class:`~fathom.core.settings.Settings` (typed loosely to avoid an import
    cycle). ``model`` is an optional per-feature override; when falsy the single, cohesive
    ``inference_model`` is used — so every chat feature shares one provider + model by default.
    ``secret_provider`` resolves the API key by reference; it defaults to the env/Docker provider
    (ADR-010) but a caller passes a store-backed one (ADR-038) so a key typed into the Settings UI
    resolves too. Raises :class:`InferenceError` (status 503) if a cloud provider is selected
    without the explicit egress gate or without a resolvable key — never silently downgrades.
    """
    from fathom.backends.remote import env_or_docker_secret_provider
    from fathom.core.settings import Settings

    assert isinstance(settings, Settings)  # noqa: S101 — typed loosely to avoid an import cycle
    resolve_secret = secret_provider or env_or_docker_secret_provider
    provider = settings.inference_provider.lower()
    # One cohesive model unless a feature explicitly overrides it.
    chosen_model = model or settings.inference_model

    if provider == "ollama":
        return OllamaProvider(
            base_url=settings.inference_ollama_url,
            model=chosen_model,
            timeout_seconds=settings.inference_timeout_seconds,
        )

    if provider == "openai":
        if not settings.inference_allow_egress:
            raise InferenceError(
                "cloud inference is disabled: set inference_allow_egress to send digests off-host "
                "(ADR-022), or use the default local 'ollama' provider",
                status_code=503,
            )
        api_key = resolve_api_key(
            settings.inference_openai_api_key,
            settings.inference_openai_key_ref,
            resolve_secret,
        )
        if not api_key:
            raise InferenceError(
                "cloud inference selected but no API key set — enter the OpenAI API key in "
                "Settings (or configure a secret reference)"
            )
        return OpenAICompatibleProvider(
            base_url=settings.inference_openai_url,
            model=_cloud_model("openai", chosen_model),
            api_key=api_key,
            timeout_seconds=settings.inference_timeout_seconds,
        )

    if provider == "anthropic":
        # Same egress gate as openai: the cloud path is refused unless egress is explicitly on and
        # a key is available (direct or by reference, ADR-010/022). No silent downgrade to local.
        if not settings.inference_allow_egress:
            raise InferenceError(
                "cloud inference is disabled: set inference_allow_egress to send prompts off-host "
                "(ADR-022), or use the default local 'ollama' provider",
                status_code=503,
            )
        api_key = resolve_api_key(
            settings.inference_anthropic_api_key,
            settings.inference_anthropic_key_ref,
            resolve_secret,
        )
        if not api_key:
            raise InferenceError(
                "cloud inference selected but no API key set — enter the Anthropic API key in "
                "Settings (or configure a secret reference)"
            )
        return AnthropicProvider(
            base_url=settings.inference_anthropic_url,
            model=_cloud_model("anthropic", chosen_model),
            api_key=api_key,
            timeout_seconds=settings.inference_timeout_seconds,
            api_version=settings.inference_anthropic_version,
        )

    raise InferenceError(f"unknown inference provider {provider!r}")
