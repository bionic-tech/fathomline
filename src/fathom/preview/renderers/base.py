"""Renderer protocol (ADR-014; preview-worker interfaces).

A renderer is the in-sandbox unit that decodes one untrusted file and emits DERIVED artifacts.
The protocol is intentionally tiny so the registry can dispatch on type and so a fake renderer
is trivial to inject in tests (the sandbox driver is faked; the real decode never runs in CI).
"""

from __future__ import annotations

from typing import Protocol

from fathom.preview.types import PreviewArtifact, ResourceCaps, SupportedType


class Renderer(Protocol):
    """Render one untrusted file's raw bytes to safe derived artifacts (decode in sandbox only).

    ``supports`` lets the registry validate dispatch; ``render`` performs the decode under the
    given :class:`~fathom.preview.types.ResourceCaps` (page/decompressed caps enforced here too,
    in addition to the OS-level cgroup/time limits the sandbox driver applies — defence in depth).
    A render that cannot be produced safely raises
    :class:`~fathom.preview.types.PreviewError`.
    """

    def supports(self, detected: SupportedType) -> bool: ...

    def render(
        self, raw: bytes, *, detected: SupportedType, caps: ResourceCaps
    ) -> list[PreviewArtifact]: ...
