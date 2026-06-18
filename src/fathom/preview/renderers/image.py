"""Image renderer — raster-only re-encode to a safe thumbnail (ADR-014, AR-0008/0017).

Runs **inside the gVisor sandbox**. Decodes the untrusted image with Pillow and **re-encodes**
it to a small raster (WebP) — the output is a freshly-rendered thumbnail, never the original
bytes and never the original container/metadata (EXIF is dropped by re-encoding from pixels).
This raster-only re-encode is the AR-0008/0017 control: an SVG is never rasterised by a browser
engine, and a polyglot/metadata-smuggling image cannot pass its original bytes through.

Pillow is lazy-imported so the core image and the test suite (which fake the sandbox) need not
carry it; it is installed only in the preview-worker sandbox image (Dockerfile.preview). A
decompression bomb is guarded by Pillow's ``MAX_IMAGE_PIXELS`` set from the caps *and* the
sandbox's OS-level memory/time caps (STRIDE D-6, defence in depth).
"""

from __future__ import annotations

import io

from fathom.preview.types import PreviewArtifact, PreviewError, ResourceCaps, SupportedType

# A fixed, safe thumbnail bound — the derived raster is at most this on a side.
_THUMBNAIL_MAX_EDGE = 512


class ImageRenderer:
    """Decode + raster-only re-encode an image to a safe WebP thumbnail (derived only)."""

    def supports(self, detected: SupportedType) -> bool:
        return detected is SupportedType.IMAGE

    def render(
        self, raw: bytes, *, detected: SupportedType, caps: ResourceCaps
    ) -> list[PreviewArtifact]:
        try:
            from PIL import Image, UnidentifiedImageError  # lazy: sandbox-only dependency
        except ImportError as exc:  # pragma: no cover — only hit if run outside the sandbox image
            raise PreviewError("image renderer unavailable", status_code=500) from exc

        # Cap the decoded pixel budget from the decompressed-bytes cap (~4 bytes/pixel) so a
        # pixel bomb is refused by the decoder, not just by the OS memory cap (D-6).
        Image.MAX_IMAGE_PIXELS = max(1, caps.max_decompressed_bytes // 4)
        try:
            with Image.open(io.BytesIO(raw)) as img:
                img = img.convert("RGB")
                img.thumbnail((_THUMBNAIL_MAX_EDGE, _THUMBNAIL_MAX_EDGE))
                width, height = img.size
                out = io.BytesIO()
                img.save(out, format="WEBP", quality=80, method=4)
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            # Corrupt / bomb / unsupported codec → graceful failure, never a 500/stack trace.
            raise PreviewError("image could not be rendered") from exc

        return [
            PreviewArtifact(
                kind="thumbnail",
                media_type="image/webp",
                data=out.getvalue(),
                meta={"width": width, "height": height, "reencoded": True},
            )
        ]
