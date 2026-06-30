"""Pluggable embedding providers (ADR-035 addendum) — the seam the concierge index talks to.

Mirrors the chat provider abstraction (``inference/__init__.py``): a small ``EmbeddingProvider``
protocol with local + cloud implementations and an egress-gated factory. The default is local Ollama
(``nomic-embed-text``, no egress); ``voyage`` (Anthropic's documented preferred embedder) and
``openai`` are added behind the **same egress gate** as the chat cloud providers — cloud is refused
unless ``inference_allow_egress`` is set and the key resolves by reference (ADR-010).

``input_type`` carries the document/query asymmetry: catalogue rows are embedded as ``document`` and
the search text as ``query`` (providers that support it — Voyage — use it; the others ignore it). No
file content is ever embedded — only names + path tails (the caller builds the text).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

import httpx

from fathom.inference.base import InferenceError
from fathom.logging import get_logger

_log = get_logger("fathom.inference.embeddings")

INPUT_DOCUMENT = "document"
INPUT_QUERY = "query"

# Cap an embed response so a misconfigured endpoint can't flood memory (mirrors the chat bound).
_MAX_EMBED_BYTES = 16 * 1024 * 1024


@runtime_checkable
class EmbeddingProvider(Protocol):
    """Embeds a batch of texts into vectors; ``input_type`` is document|query (ADR-035 addendum)."""

    async def embed(self, texts: list[str], *, input_type: str) -> list[list[float]]: ...


def _check_response(resp: httpx.Response) -> None:
    if resp.status_code != 200:
        _log.warning("embed non-200", extra={"status": resp.status_code})
        raise InferenceError("embedding provider error", status_code=503)
    if len(resp.content) > _MAX_EMBED_BYTES:
        raise InferenceError("embedding response too large", status_code=502)


def _floats(vectors: object, expected: int) -> list[list[float]]:
    if not isinstance(vectors, list) or len(vectors) != expected:
        raise InferenceError("embedding count mismatch", status_code=502)
    out: list[list[float]] = []
    for v in vectors:
        if not isinstance(v, list):
            raise InferenceError("embedding response malformed", status_code=502)
        out.append([float(x) for x in v])
    return out


class OllamaEmbedder:
    """Local Ollama ``/api/embed`` (default, no egress). Ignores input_type (symmetric model)."""

    def __init__(self, *, base_url: str, model: str, timeout_seconds: float) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout_seconds

    async def embed(self, texts: list[str], *, input_type: str) -> list[list[float]]:
        if not texts:
            return []
        payload = {"model": self._model, "input": texts}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(f"{self._base_url}/api/embed", json=payload)
        except httpx.TimeoutException as exc:
            raise InferenceError("embedding timed out", status_code=504) from exc
        except httpx.HTTPError as exc:
            raise InferenceError("embedding provider unreachable", status_code=503) from exc
        _check_response(resp)
        try:
            vectors = resp.json()["embeddings"]
        except (KeyError, TypeError, ValueError) as exc:
            raise InferenceError("embedding response malformed", status_code=502) from exc
        return _floats(vectors, len(texts))


class VoyageEmbedder:
    """Voyage AI ``/v1/embeddings`` (Anthropic's preferred embedder; egress). Honours input_type."""

    def __init__(
        self, *, base_url: str, model: str, api_key: str, timeout_seconds: float
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout_seconds

    async def embed(self, texts: list[str], *, input_type: str) -> list[list[float]]:
        if not texts:
            return []
        # Voyage maps document/query directly; pass through (None for an unknown type).
        vtype = input_type if input_type in (INPUT_DOCUMENT, INPUT_QUERY) else None
        payload: dict[str, object] = {"model": self._model, "input": texts}
        if vtype is not None:
            payload["input_type"] = vtype
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/v1/embeddings",
                    json=payload,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
        except httpx.TimeoutException as exc:
            raise InferenceError("embedding timed out", status_code=504) from exc
        except httpx.HTTPError as exc:
            raise InferenceError("embedding provider unreachable", status_code=503) from exc
        _check_response(resp)
        try:
            data = resp.json()["data"]
            vectors = [item["embedding"] for item in data]
        except (KeyError, TypeError, ValueError) as exc:
            raise InferenceError("embedding response malformed", status_code=502) from exc
        return _floats(vectors, len(texts))


class OpenAIEmbedder:
    """OpenAI-compatible ``/embeddings`` (egress). No ``input_type`` (ignored)."""

    def __init__(
        self, *, base_url: str, model: str, api_key: str, timeout_seconds: float
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout_seconds

    async def embed(self, texts: list[str], *, input_type: str) -> list[list[float]]:
        if not texts:
            return []
        payload = {"model": self._model, "input": texts}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/embeddings",
                    json=payload,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
        except httpx.TimeoutException as exc:
            raise InferenceError("embedding timed out", status_code=504) from exc
        except httpx.HTTPError as exc:
            raise InferenceError("embedding provider unreachable", status_code=503) from exc
        _check_response(resp)
        try:
            data = resp.json()["data"]
            vectors = [item["embedding"] for item in data]
        except (KeyError, TypeError, ValueError) as exc:
            raise InferenceError("embedding response malformed", status_code=502) from exc
        return _floats(vectors, len(texts))


def build_embedding_provider(
    settings: object,
    *,
    secret_provider: Callable[[str], str] | None = None,
) -> EmbeddingProvider:
    """Build the configured :class:`EmbeddingProvider` (fail-closed on egress; ADR-035 addendum).

    Default local Ollama (no egress). ``voyage``/``openai`` are constructed only when
    ``inference_allow_egress`` is True and the key resolves by reference — the same gate as the chat
    cloud providers (ADR-010/022). ``secret_provider`` defaults to env/Docker but a caller passes a
    store-backed one (ADR-038) so a key set in the UI resolves too.
    """
    from fathom.backends.remote import env_or_docker_secret_provider
    from fathom.core.settings import Settings

    assert isinstance(settings, Settings)  # noqa: S101 — typed loosely to avoid an import cycle
    resolve_secret = secret_provider or env_or_docker_secret_provider
    provider = settings.concierge_embedding_provider.lower()
    model = settings.concierge_embedding_model
    timeout = settings.inference_timeout_seconds

    if provider == "ollama":
        base = settings.concierge_embedding_url or settings.inference_ollama_url
        return OllamaEmbedder(base_url=base, model=model, timeout_seconds=timeout)

    if provider in ("voyage", "openai"):
        if not settings.inference_allow_egress:
            raise InferenceError(
                "cloud embedding is disabled: set inference_allow_egress to send names off-host "
                "(ADR-035), or use the default local 'ollama' embedder",
                status_code=503,
            )
        from fathom.inference import resolve_api_key

        api_key = resolve_api_key(
            settings.concierge_embedding_api_key,
            settings.concierge_embedding_key_ref,
            resolve_secret,
        )
        if not api_key:
            raise InferenceError(
                "cloud embedder selected but no API key set — enter the embedding API key in "
                "Settings (or configure a secret reference)"
            )
        if provider == "voyage":
            base = settings.concierge_embedding_url or "https://api.voyageai.com"
            return VoyageEmbedder(
                base_url=base, model=model, api_key=api_key, timeout_seconds=timeout
            )
        base = settings.concierge_embedding_url or "https://api.openai.com/v1"
        return OpenAIEmbedder(base_url=base, model=model, api_key=api_key, timeout_seconds=timeout)

    raise InferenceError(f"unknown embedding provider {provider!r}")
