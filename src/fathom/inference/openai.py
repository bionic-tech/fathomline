"""OpenAI-compatible inference provider (ADR-022) — opt-in, egress, cloud.

Works against any OpenAI-compatible ``/chat/completions`` endpoint (OpenAI, Groq, …). This path
sends the content-derived digest OFF the operator's host, so it is constructed only behind the
explicit egress gate (enforced by the factory) and the API key is resolved by reference from the
secret backend (ADR-010), never embedded or logged. Output is validated against the requested
schema here exactly as the local path.
"""

from __future__ import annotations

import json

import httpx
from pydantic import ValidationError

from fathom.inference.base import InferenceError, T
from fathom.logging import get_logger

_log = get_logger("fathom.inference.openai")

_MAX_OUTPUT_BYTES = 2 * 1024 * 1024


class OpenAICompatibleProvider:
    """An :class:`~fathom.inference.base.InferenceProvider` over an OpenAI-compatible endpoint."""

    def __init__(self, *, base_url: str, model: str, api_key: str, timeout_seconds: float) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout_seconds

    async def complete(self, *, system: str, user: str, schema: type[T]) -> T:
        # json_object response-format is the broadly-supported structured mode (OpenAI + Groq);
        # the schema is also injected into the system prompt for adherence, and re-validated below.
        schema_hint = json.dumps(schema.model_json_schema())
        sys_prompt = f"{system}\n\nRespond with JSON matching this schema:\n{schema_hint}"
        payload = {
            "model": self._model,
            "temperature": 0,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _log.info("inference egress", extra={"endpoint": self._base_url, "model": self._model})
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions", json=payload, headers=headers
                )
        except httpx.TimeoutException as exc:
            raise InferenceError("inference timed out", status_code=504) from exc
        except httpx.HTTPError as exc:
            raise InferenceError("inference provider unreachable", status_code=503) from exc

        if resp.status_code != 200:
            _log.warning("openai-compat non-200", extra={"status": resp.status_code})
            raise InferenceError("inference provider error", status_code=503)

        try:
            content: str = resp.json()["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise InferenceError("inference response malformed", status_code=502) from exc

        if len(content.encode("utf-8", "ignore")) > _MAX_OUTPUT_BYTES:
            raise InferenceError("inference response too large", status_code=502)

        try:
            return schema.model_validate_json(content)
        except ValidationError as exc:
            raise InferenceError("inference output did not match schema", status_code=502) from exc
