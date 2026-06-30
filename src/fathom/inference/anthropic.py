"""Anthropic Messages-API inference provider (ADR-022) — opt-in, egress, cloud.

Talks to the Anthropic Messages API (``/v1/messages``). Structured output is obtained the robust
way for Anthropic: a single tool is defined whose ``input_schema`` IS the requested Pydantic
schema, and ``tool_choice`` forces the model to call it — so the model returns a structured
``input`` object rather than free-form text we'd have to coax into JSON. The object is re-validated
against the schema here exactly as the local path; a refused or malformed answer is never returned
as raw text.

This path sends the prompt OFF the operator's host, so it is constructed only behind the explicit
egress gate (enforced by the factory) and the API key is resolved by reference from the secret
backend (ADR-010), never embedded or logged.
"""

from __future__ import annotations

import json

import httpx
from pydantic import ValidationError

from fathom.inference.base import InferenceError, T
from fathom.logging import get_logger

_log = get_logger("fathom.inference.anthropic")

_MAX_OUTPUT_BYTES = 2 * 1024 * 1024
# The single tool the model is forced to call; its input_schema is the requested Pydantic schema.
_TOOL_NAME = "emit_result"


class AnthropicProvider:
    """An :class:`~fathom.inference.base.InferenceProvider` over the Anthropic Messages API."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str,
        timeout_seconds: float,
        api_version: str = "2023-06-01",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._api_version = api_version

    async def complete(self, *, system: str, user: str, schema: type[T]) -> T:
        # Force a single tool call whose input_schema is the requested schema → the model returns a
        # structured object, not prose. Re-validated below; the model never has free-form authority.
        payload = {
            "model": self._model,
            "max_tokens": 4096,
            "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "tools": [
                {
                    "name": _TOOL_NAME,
                    "description": "Return the result as structured data matching the schema.",
                    "input_schema": schema.model_json_schema(),
                }
            ],
            "tool_choice": {"type": "tool", "name": _TOOL_NAME},
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": self._api_version,
            "content-type": "application/json",
        }
        _log.info("inference egress", extra={"endpoint": self._base_url, "model": self._model})
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/v1/messages", json=payload, headers=headers
                )
        except httpx.TimeoutException as exc:
            raise InferenceError("inference timed out", status_code=504) from exc
        except httpx.HTTPError as exc:
            raise InferenceError("inference provider unreachable", status_code=503) from exc

        if resp.status_code != 200:
            _log.warning("anthropic non-200", extra={"status": resp.status_code})
            raise InferenceError("inference provider error", status_code=503)

        try:
            blocks = resp.json()["content"]
            tool_input = next(b["input"] for b in blocks if b.get("type") == "tool_use")
        except (json.JSONDecodeError, KeyError, TypeError, StopIteration) as exc:
            raise InferenceError("inference response malformed", status_code=502) from exc

        if len(json.dumps(tool_input).encode("utf-8", "ignore")) > _MAX_OUTPUT_BYTES:
            raise InferenceError("inference response too large", status_code=502)

        try:
            return schema.model_validate(tool_input)
        except ValidationError as exc:
            _log.warning("anthropic output failed schema", extra={"model": self._model})
            raise InferenceError("inference output did not match schema", status_code=502) from exc
