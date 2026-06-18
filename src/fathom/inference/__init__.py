"""Pluggable LLM inference (ADR-022) — the seam the Organize feature (ADR-021) talks to.

``build_inference_provider(settings)`` is the factory: it returns the configured provider and is
the single place the **egress gate** is enforced — the cloud provider is constructed only when
``inference_allow_egress`` is True and its API key resolves from the secret backend (ADR-010). The
default is the local Ollama path (on-host, no egress).
"""

from __future__ import annotations

from fathom.inference.base import InferenceError, InferenceProvider
from fathom.inference.ollama import OllamaProvider
from fathom.inference.openai import OpenAICompatibleProvider

__all__ = [
    "InferenceError",
    "InferenceProvider",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "build_inference_provider",
]


def build_inference_provider(settings: object) -> InferenceProvider:
    """Build the configured :class:`InferenceProvider` from settings (fail-closed on egress).

    ``settings`` is a :class:`~fathom.core.settings.Settings` (typed loosely to avoid an import
    cycle). Raises :class:`InferenceError` (status 503) if the cloud provider is selected without
    the explicit egress gate or without a resolvable key — never silently downgrades or leaks.
    """
    from fathom.backends.remote import env_or_docker_secret_provider
    from fathom.core.settings import Settings

    assert isinstance(settings, Settings)  # noqa: S101 — typed loosely to avoid an import cycle
    provider = settings.inference_provider.lower()

    if provider == "ollama":
        return OllamaProvider(
            base_url=settings.inference_ollama_url,
            model=settings.organize_model,
            timeout_seconds=settings.inference_timeout_seconds,
        )

    if provider == "openai":
        if not settings.inference_allow_egress:
            raise InferenceError(
                "cloud inference is disabled: set inference_allow_egress to send digests off-host "
                "(ADR-022), or use the default local 'ollama' provider",
                status_code=503,
            )
        if not settings.inference_openai_key_ref:
            raise InferenceError("cloud inference selected but no API key reference configured")
        api_key = env_or_docker_secret_provider(settings.inference_openai_key_ref)
        if not api_key:
            raise InferenceError("cloud inference API key reference did not resolve")
        return OpenAICompatibleProvider(
            base_url=settings.inference_openai_url,
            model=settings.organize_model,
            api_key=api_key,
            timeout_seconds=settings.inference_timeout_seconds,
        )

    raise InferenceError(f"unknown inference provider {provider!r}")
