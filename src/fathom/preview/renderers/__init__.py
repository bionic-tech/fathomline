"""Renderer registry, keyed by detected type (ADR-014; preview-worker interfaces).

A :class:`Renderer` turns one untrusted file's raw bytes into a list of safe DERIVED artifacts.
**These run inside the gVisor sandbox** (the preview-worker sandbox image) — the decode of
untrusted content happens *only* there, never in core/scanner/read (security_constraints,
file-mgmt §5.2). The heavy decode libraries (Pillow, pygments, LibreOffice) are therefore
lazy-imported inside each renderer so the core image / test suite need not carry them.

The registry maps a :class:`~fathom.preview.types.SupportedType` to the one renderer that
handles it; :func:`get_renderer` is the dispatch oracle the in-sandbox entrypoint calls.
"""

from __future__ import annotations

from fathom.preview.renderers.base import Renderer
from fathom.preview.renderers.document import DocumentRenderer
from fathom.preview.renderers.image import ImageRenderer
from fathom.preview.renderers.text import TextRenderer
from fathom.preview.types import ResourceCaps, SupportedType

_REGISTRY: dict[SupportedType, Renderer] = {
    SupportedType.IMAGE: ImageRenderer(),
    SupportedType.PDF: DocumentRenderer(),
    SupportedType.OFFICE: DocumentRenderer(),
    SupportedType.TEXT: TextRenderer(),
    SupportedType.CODE: TextRenderer(),
    SupportedType.MARKDOWN: TextRenderer(),
}


def get_renderer(detected: SupportedType) -> Renderer:
    """Return the renderer for ``detected`` (KeyError-free: every SupportedType is registered)."""
    return _REGISTRY[detected]


__all__ = [
    "DocumentRenderer",
    "ImageRenderer",
    "Renderer",
    "ResourceCaps",
    "TextRenderer",
    "get_renderer",
]
