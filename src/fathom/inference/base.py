"""The ``InferenceProvider`` seam (ADR-022).

Fathom's only AI surface is the content-aware Organize feature (ADR-021); this is the thin,
reusable plug it talks to. A provider has one job: take a system+user prompt and a Pydantic output
schema and return a **validated instance** (or raise a typed :class:`InferenceError`). No
streaming, no chat history, no tool-use — the model proposes structured data and nothing else, so
business logic never sees free-form text and the model has no authority.

Structural typing (``typing.Protocol``) per code-quality rule #9, matching the other Fathom plugin
points (``StorageBackend``, ``PlatformAdapter``, the preview ``FileFetcher``).
"""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class InferenceError(RuntimeError):
    """A provider failed — unreachable, timed out, refused, or returned unparseable output.

    Carries an HTTP-ish ``status_code`` so the route can map it to a sanitised problem+json without
    leaking provider internals. The default 503 means "inference is unavailable"; a 502 means the
    model answered but the answer could not be validated against the requested schema.
    """

    def __init__(self, message: str, *, status_code: int = 503) -> None:
        super().__init__(message)
        self.status_code = status_code


@runtime_checkable
class InferenceProvider(Protocol):
    """Return a schema-validated structured completion for one prompt (no streaming/tools)."""

    async def complete(self, *, system: str, user: str, schema: type[T]) -> T:
        """Run the prompt and return an instance of ``schema``.

        Implementations MUST validate the model's output against ``schema`` at the boundary and
        raise :class:`InferenceError` on any failure — a malformed or refused response is never
        returned as raw text. They MUST enforce a hard timeout and a bounded output size.
        """
        ...
