"""Document renderer — PDF/Office first-page raster + text snippet (ADR-014).

Runs **inside the gVisor sandbox**. Converts the first page(s) of a PDF/Office document to a
raster image and extracts a bounded text snippet, via **headless LibreOffice + a raster
backend** invoked as a subprocess *within* the sandbox container. Only the derived raster and
the extracted text leave the sandbox — never the original document, never raw HTML/SVG
(security_constraints).

The page-count cap (``caps.max_pages``) and the decompressed-bytes cap bound a huge-page-count /
decompression bomb (STRIDE D-6) in addition to the OS-level cgroup/time caps the sandbox driver
applies. The conversion tooling is lazy-invoked (and may be absent in the core image / test
suite, which fake the sandbox); a missing toolchain or a failed/over-cap conversion raises
:class:`~fathom.preview.types.PreviewError` so the route fails gracefully.

This module deliberately holds only the *contract and orchestration* of the conversion; the
heavy LibreOffice invocation lives behind :func:`_convert_first_page`, which the sandbox image
provides. Keeping the decode out of any importable-at-core code path is the point (file-mgmt
§5.2: no format parsing in core/scanner/read).
"""

from __future__ import annotations

from fathom.preview.types import PreviewArtifact, PreviewError, ResourceCaps, SupportedType

# Bound the extracted text snippet so a document cannot exfiltrate unbounded content via preview.
_TEXT_SNIPPET_MAX_CHARS = 4000


class DocumentRenderer:
    """Render the first page(s) of a PDF/Office document to a raster + a bounded text snippet."""

    def supports(self, detected: SupportedType) -> bool:
        return detected in (SupportedType.PDF, SupportedType.OFFICE)

    def render(
        self, raw: bytes, *, detected: SupportedType, caps: ResourceCaps
    ) -> list[PreviewArtifact]:
        if len(raw) > caps.max_decompressed_bytes:
            # Coarse pre-decode guard; the OS-level caps are the hard backstop (D-6).
            raise PreviewError("document exceeds size cap", status_code=413)
        try:
            raster_png, snippet, page_count = _convert_first_page(
                raw, detected=detected, max_pages=caps.max_pages
            )
        except FileNotFoundError as exc:  # pragma: no cover — toolchain absent outside sandbox
            raise PreviewError("document renderer unavailable", status_code=500) from exc
        except (RuntimeError, ValueError, OSError) as exc:
            raise PreviewError("document could not be rendered") from exc

        artifacts: list[PreviewArtifact] = [
            PreviewArtifact(
                kind="page_raster",
                media_type="image/png",
                data=raster_png,
                meta={"pages_rendered": min(page_count, caps.max_pages), "total_pages": page_count},
            )
        ]
        if snippet:
            artifacts.append(
                PreviewArtifact(
                    kind="text_snippet",
                    media_type="text/plain",
                    data=snippet[:_TEXT_SNIPPET_MAX_CHARS].encode("utf-8"),
                    meta={"truncated": len(snippet) > _TEXT_SNIPPET_MAX_CHARS},
                )
            )
        return artifacts


def _convert_first_page(
    raw: bytes, *, detected: SupportedType, max_pages: int
) -> tuple[bytes, str, int]:
    """Convert the first page(s) to a PNG raster + extract a text snippet (sandbox-only).

    Implemented by the sandbox image's LibreOffice/raster toolchain. In the core image / test
    environment the toolchain is absent and this raises ``FileNotFoundError`` (mapped to a
    sanitised 500 by the caller) — by design, the real decode runs ONLY inside the sandbox
    (security_constraints; file-mgmt §5.2). The sandbox entrypoint overrides this with the
    concrete `soffice --headless` + page-rasterisation pipeline.
    """
    raise FileNotFoundError("document conversion toolchain is sandbox-only")
