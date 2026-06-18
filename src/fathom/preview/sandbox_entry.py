"""In-sandbox preview entrypoint (ADR-014) — the ONLY place untrusted content is decoded.

This module is the process the runsc container runs (``python -m fathom.preview.sandbox_entry``).
It reads one untrusted file from **stdin**, **re-detects** the type by magic bytes (never trusts
the requested ``--type`` blindly), dispatches to the in-sandbox renderer, and writes the DERIVED
artifacts as JSON to **stdout** (base64 bytes). It opens no socket, writes no file outside the
tmpfs scratch, and exits non-zero on any failure so the driver fails gracefully (D-6/E-7).

It is invoked only inside the gVisor sandbox; running it in core is a no-op except for the tiny
text path (the heavy decoders are absent there). Keeping the decode behind this entrypoint is the
whole point — core/scanner/read never import a decoder (file-mgmt §5.2).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys

from fathom.preview.renderers import get_renderer
from fathom.preview.types import (
    PreviewArtifact,
    PreviewError,
    ResourceCaps,
    SupportedType,
    detect_type,
)

# How much of stdin to sniff for magic-byte detection.
_SNIFF_BYTES = 4096


def _build_caps(args: argparse.Namespace) -> ResourceCaps:
    # CPU/memory/time are enforced by the container runtime; the renderer-level caps (pages,
    # decompressed bytes) are passed through so the decoder refuses a bomb early (defence in depth).
    return ResourceCaps(
        cpu=1.0,
        mem_bytes=64 * 1024 * 1024,
        time_s=1.0,
        max_pages=args.max_pages,
        max_decompressed_bytes=args.max_decompressed_bytes,
    )


def _resolve_type(raw: bytes, requested: str) -> SupportedType:
    """Re-detect the type inside the sandbox; fall back to the requested class for text-family.

    Magic-byte detection is authoritative for binary formats (image/PDF/Office). For the
    text-family (text/code/markdown), which has no single magic number, the requested class is
    honoured only after confirming the bytes look like inert text — never trusting the flag to
    route binary content to the text renderer.
    """
    sniffed = detect_type(raw[:_SNIFF_BYTES])
    requested_type = SupportedType(requested)
    if sniffed is not None:
        if requested_type in (SupportedType.CODE, SupportedType.MARKDOWN) and (
            sniffed is SupportedType.TEXT
        ):
            # Requested code/markdown and the bytes are inert text → honour the finer class.
            return requested_type
        return sniffed
    raise PreviewError("unsupported or unrecognised content")


def _emit(artifacts: list[PreviewArtifact]) -> None:
    payload = {
        "artifacts": [
            {
                "kind": a.kind,
                "media_type": a.media_type,
                "data_b64": base64.b64encode(a.data).decode("ascii"),
                "meta": a.meta,
            }
            for a in artifacts
        ]
    }
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    """Read stdin, render to derived artifacts, emit JSON. Returns a process exit code."""
    parser = argparse.ArgumentParser(prog="fathom-preview-sandbox")
    parser.add_argument("--type", required=True)
    parser.add_argument("--max-pages", type=int, required=True)
    parser.add_argument("--max-decompressed-bytes", type=int, required=True)
    args = parser.parse_args(argv)

    raw = sys.stdin.buffer.read()
    caps = _build_caps(args)
    try:
        detected = _resolve_type(raw, args.type)
        renderer = get_renderer(detected)
        artifacts = renderer.render(raw, detected=detected, caps=caps)
    except PreviewError as exc:
        sys.stderr.write(exc.reason)
        return 1
    _emit(artifacts)
    return 0


if __name__ == "__main__":  # pragma: no cover — container entrypoint
    raise SystemExit(main())
