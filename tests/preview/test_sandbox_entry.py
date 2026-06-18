"""In-sandbox entrypoint — type re-detection + derived JSON emit (ADR-014).

The entrypoint re-detects the type by magic bytes (never trusting the requested --type flag for
binary content) and emits derived artifacts as JSON on stdout. Run in-process here over the text
path (the only renderer with no heavy dependency); binary decoders are sandbox-only.
"""

from __future__ import annotations

import base64
import json

import pytest

from fathom.preview.sandbox_entry import _resolve_type, main
from fathom.preview.types import PreviewError, SupportedType


def test_resolve_type_prefers_magic_over_flag() -> None:
    """A PNG magic with a requested 'text' flag is detected as image, not text (no flag trust)."""
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    assert _resolve_type(png, "text") is SupportedType.IMAGE


def test_resolve_type_honours_code_for_text_bytes() -> None:
    """Inert text requested as 'code' keeps the finer code class (text-family only)."""
    assert _resolve_type(b"print('hi')\n", "code") is SupportedType.CODE


def test_resolve_type_unsupported_raises() -> None:
    with pytest.raises(PreviewError):
        _resolve_type(b"\x00\x01\x02\x03binarybomb", "text")


def test_main_emits_derived_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The entrypoint reads stdin, renders, and writes derived artifacts as base64 JSON."""
    import io
    import sys

    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"hello = 1\n")))
    rc = main(["--type", "text", "--max-pages", "50", "--max-decompressed-bytes", "1048576"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["artifacts"]
    first = out["artifacts"][0]
    # Derived (decoded back) is NOT the raw input passthrough beyond the snippet transform.
    decoded = base64.b64decode(first["data_b64"])
    assert b"hello = 1" in decoded  # the text snippet is the file text, bounded + re-encoded
    assert first["media_type"] in ("text/plain", "application/json")
