"""Preview domain types + magic-byte type detection (ADR-014; preview-worker interfaces).

The wire/derived-artifact shapes for the sandboxed preview path. The cardinal rule is encoded
in the types: a :class:`PreviewArtifact` is a **derived** artifact only — a re-encoded raster
thumbnail, a first-page page-raster, or an extracted/highlighted text snippet — never the raw
original bytes, never raw SVG/HTML (ADR-014, sec-arch §6).

Type detection is by **magic bytes, not file extension** (security_constraints: "not trusting
extension"): an attacker who renames ``bomb.zip`` to ``photo.jpg`` must not get it dispatched to
the image decoder on the strength of the name. :func:`detect_type` sniffs a short prefix; an
unknown or deferred (video/audio) type is returned as :data:`None`/``UNSUPPORTED`` so the route
fails gracefully with a sanitised problem+json rather than guessing.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# The kinds of derived artifact the sandbox may emit. Each is a *transformed* representation —
# never the raw input (ADR-014). ``code_render`` is a server-side syntax-highlighted, structured
# token list (NOT raw HTML/SVG): the browser renders it from safe data, not an injected document.
ArtifactKind = Literal["thumbnail", "page_raster", "text_snippet", "code_render"]


class SupportedType(StrEnum):
    """Renderable v1 preview types (ADR-014). Video/audio poster/cover-art deferred."""

    IMAGE = "image"
    PDF = "pdf"
    OFFICE = "office"
    TEXT = "text"
    CODE = "code"
    MARKDOWN = "markdown"


# Magic-byte signatures keyed to a type. Sniffed against the input prefix; extension is ignored
# (security_constraints). Office/PDF/image are content-sniffed; text/code/markdown have no single
# magic number, so they are inferred last as a fallback only when the bytes look like inert text.
_IMAGE_MAGIC: tuple[bytes, ...] = (
    b"\xff\xd8\xff",  # JPEG
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"GIF87a",
    b"GIF89a",
    b"BM",  # BMP
    b"II*\x00",  # TIFF little-endian
    b"MM\x00*",  # TIFF big-endian
)
_PDF_MAGIC = b"%PDF-"
# ZIP local-file header — modern Office (OOXML) and OpenDocument are ZIP containers. The worker
# disambiguates Office from a plain archive *inside the sandbox*; here a ZIP magic on an
# Office-class request is treated as OFFICE (the route still resolves the catalogue entry, never
# the client's claim).
_ZIP_MAGIC = b"PK\x03\x04"
# Legacy OLE2 (.doc/.xls/.ppt) compound-document signature.
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _looks_like_text(prefix: bytes) -> bool:
    """Heuristic: a prefix with no NUL and mostly printable/whitespace bytes is inert text."""
    if not prefix:
        return False
    if b"\x00" in prefix:
        return False
    printable = sum(1 for b in prefix if b in (9, 10, 13) or 32 <= b <= 126 or b >= 128)
    return printable / len(prefix) > 0.85


def detect_type(prefix: bytes) -> SupportedType | None:
    """Detect a :class:`SupportedType` from a content prefix by magic bytes (not extension).

    Returns ``None`` for an unknown or deferred (video/audio/archive) type so the caller can fail
    gracefully. Office (ZIP/OLE2) is reported as :attr:`SupportedType.OFFICE`; a bare ZIP that is
    not an Office container is still sniffed as OFFICE here and rejected inside the sandbox if it
    is not actually renderable — the decode never happens in core (security_constraints).
    """
    if prefix.startswith(_IMAGE_MAGIC):
        return SupportedType.IMAGE
    if prefix.startswith(_PDF_MAGIC):
        return SupportedType.PDF
    if prefix.startswith(_OLE2_MAGIC) or prefix.startswith(_ZIP_MAGIC):
        return SupportedType.OFFICE
    if _looks_like_text(prefix):
        return SupportedType.TEXT
    return None


class PreviewRequest(BaseModel):
    """A request to render a single catalogued entry (resolved server-side; never a path).

    Only the surrogate ``entry_id`` crosses the boundary; the host/volume/path/content-hash are
    resolved from the catalogue server-side (interfaces: "never trust client path"). This keeps
    the preview path from ever acting on an attacker-supplied path string.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: int = Field(ge=1)


class PreviewArtifact(BaseModel):
    """One DERIVED preview artifact (ADR-014). Never the raw original; never raw SVG/HTML.

    ``data`` is the derived bytes (a re-encoded raster, or a UTF-8 text/JSON snippet) — already
    transformed by the sandbox. ``media_type`` is the artifact's safe type (e.g. ``image/webp``,
    ``text/plain``), not the source file's. ``meta`` carries small structured render facts (page
    counts, truncation flags) — no raw content.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ArtifactKind
    media_type: str = Field(min_length=1, max_length=128)
    data: bytes
    meta: dict[str, str | int | bool] = Field(default_factory=dict)


class PreviewResult(BaseModel):
    """The render outcome for one entry — a list of derived artifacts + provenance.

    ``cache_hit`` records whether the artifacts came from the encrypted cache or a fresh render;
    ``sandbox_job_id`` is the per-render ephemeral container id (audit-before-serve, file-mgmt
    §4.2). The result carries no raw bytes (every artifact is derived).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: int
    type: SupportedType
    artifacts: list[PreviewArtifact]
    cache_hit: bool = False
    sandbox_job_id: str = Field(min_length=1)


class PreviewError(Exception):
    """A render could not be produced safely (unsupported, oversized, bomb, or sandbox failure).

    Carries a ``reason`` slug the route maps to a sanitised RFC-9457 problem+json — no internal
    path / stack trace ever reaches the client (security_constraints; ADD 07 §3).
    """

    def __init__(self, reason: str, *, status_code: int = 422) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


class ResourceCaps(BaseModel):
    """Per-render CPU/memory/time/page + max-decompressed caps — the bomb guard (STRIDE D-6).

    Config-driven (settings) so the concrete owner-set limits (1 CPU, 512 MiB, 10s, 50 pages,
    100 MiB decompressed) are enforced at one place and the sandbox driver kills any render that
    breaches them rather than letting a decompression/page bomb exhaust the host.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    cpu: float = Field(gt=0)
    mem_bytes: int = Field(ge=64 * 1024 * 1024)
    time_s: float = Field(gt=0)
    max_pages: int = Field(ge=1)
    max_decompressed_bytes: int = Field(ge=1024 * 1024)
