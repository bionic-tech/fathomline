"""Text/code/markdown renderer — safe structured highlight (ADR-014).

Runs **inside the gVisor sandbox**. Produces a syntax-highlighted render for text/code/markdown
as a **structured token list** (JSON), never raw HTML or SVG (security_constraints, ADR-014):
the browser renders the tokens from safe data, so there is no document/markup injection surface.
A bounded ``text_snippet`` is also emitted so a client with no highlighter still has plain text.

Pygments is lazy-imported and optional: when present, the tokeniser yields ``(token_type, text)``
pairs the SPA styles; when absent (e.g. the minimal test env) the renderer degrades to a plain,
escaped text snippet only — still safe, just unstyled. Either way the output is derived and
bounded; the raw original never reaches the browser.
"""

from __future__ import annotations

import json

from fathom.preview.types import PreviewArtifact, PreviewError, ResourceCaps, SupportedType

# Bound the highlighted/plain render so a giant text file cannot stream unbounded content.
_MAX_RENDER_CHARS = 64 * 1024


class TextRenderer:
    """Render text/code/markdown to a safe structured highlight + a bounded plain snippet."""

    def supports(self, detected: SupportedType) -> bool:
        return detected in (SupportedType.TEXT, SupportedType.CODE, SupportedType.MARKDOWN)

    def render(
        self, raw: bytes, *, detected: SupportedType, caps: ResourceCaps
    ) -> list[PreviewArtifact]:
        if len(raw) > caps.max_decompressed_bytes:
            raise PreviewError("text exceeds size cap", status_code=413)
        try:
            text = raw.decode("utf-8", errors="replace")[:_MAX_RENDER_CHARS]
        except UnicodeError as exc:  # pragma: no cover — replace makes this unreachable
            raise PreviewError("text could not be decoded") from exc

        artifacts: list[PreviewArtifact] = [
            PreviewArtifact(
                kind="text_snippet",
                media_type="text/plain",
                data=text.encode("utf-8"),
                meta={"truncated": len(raw) > _MAX_RENDER_CHARS, "lines": text.count("\n") + 1},
            )
        ]
        tokens = _highlight_tokens(text)
        if tokens is not None:
            # Structured token list as JSON — NOT raw HTML/SVG (the SPA styles it from data).
            artifacts.append(
                PreviewArtifact(
                    kind="code_render",
                    media_type="application/json",
                    data=json.dumps({"tokens": tokens}).encode("utf-8"),
                    meta={"token_count": len(tokens), "highlighted": True},
                )
            )
        return artifacts


def _highlight_tokens(text: str) -> list[list[str]] | None:
    """Return ``[token_type, text]`` pairs via Pygments, or ``None`` if it is unavailable.

    Pygments is sandbox-only and optional; absent it, the caller emits the plain snippet alone.
    The token list is safe structured data (no markup), so there is no XSS/injection surface.
    """
    try:
        from pygments import lex  # lazy: sandbox-only dependency
        from pygments.lexers import guess_lexer
    except ImportError:
        return None
    try:
        lexer = guess_lexer(text)
        return [[str(tok), value] for tok, value in lex(text, lexer)]
    except Exception:  # any lexer failure degrades to the plain snippet, never a 500
        return None
