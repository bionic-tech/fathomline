"""Local Ollama inference provider (ADR-022) — the default, on-host, no-egress path.

Talks to a local Ollama server's ``/api/chat`` with ``format`` set to the requested Pydantic
schema's JSON Schema (Ollama structured outputs), so the model is constrained to emit
schema-conforming JSON. The response content is re-validated against the Pydantic model here — the
provider never returns text the schema did not accept. "Incognito" by construction: nothing leaves
the operator's host.
"""

from __future__ import annotations

import json

import httpx
from pydantic import ValidationError

from fathom.inference.base import InferenceError, T
from fathom.logging import get_logger

_log = get_logger("fathom.inference.ollama")

# Refuse to buffer an unbounded model response into memory (STRIDE D-6). 2 MiB is far more than any
# Organize proposal needs; a model that floods past it is treated as a failure, not parsed.
_MAX_OUTPUT_BYTES = 2 * 1024 * 1024


class OllamaProvider:
    """An :class:`~fathom.inference.base.InferenceProvider` over a local Ollama server."""

    def __init__(self, *, base_url: str, model: str, timeout_seconds: float) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout_seconds

    async def complete(self, *, system: str, user: str, schema: type[T]) -> T:
        payload = {
            "model": self._model,
            "stream": False,
            # Keep the model resident between requests: a cold load of a multi-GB model dominates
            # latency on CPU, so an Organize feature used repeatedly should not re-pay it each call.
            "keep_alive": "30m",
            # Ollama structured outputs: constrain generation to the schema (Ollama >= 0.5). This is
            # measurably FASTER than unconstrained ``format: "json"`` on a small local model — the
            # grammar stops the model as soon as the structure is complete rather than letting it
            # ramble toward num_predict. Keep the output schema lean (no per-item prose) so the
            # token count — the real cost on CPU — stays small.
            "format": schema.model_json_schema(),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            # Deterministic + bounded: temperature 0 for stable structure; cap generated tokens so a
            # runaway model cannot spin past the timeout producing megabytes of JSON.
            "options": {"temperature": 0, "num_predict": 4096},
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(f"{self._base_url}/api/chat", json=payload)
        except httpx.TimeoutException as exc:
            raise InferenceError("inference timed out", status_code=504) from exc
        except httpx.HTTPError as exc:
            raise InferenceError("inference provider unreachable", status_code=503) from exc

        if resp.status_code != 200:
            _log.warning("ollama non-200", extra={"status": resp.status_code})
            raise InferenceError("inference provider error", status_code=503)

        try:
            body = resp.json()
            content: str = body["message"]["content"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise InferenceError("inference response malformed", status_code=502) from exc

        if len(content.encode("utf-8", "ignore")) > _MAX_OUTPUT_BYTES:
            raise InferenceError("inference response too large", status_code=502)

        try:
            return schema.model_validate_json(content)
        except ValidationError as exc:
            _log.warning("ollama output failed schema", extra={"model": self._model})
            raise InferenceError("inference output did not match schema", status_code=502) from exc
