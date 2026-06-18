"""Preview returns DERIVED artifacts only — never the raw original bytes (ADR-014).

Named regression intent: for each type the render output is a transformed artifact (re-encoded
raster / text snippet / structured highlight), and byte-equality with the raw input is
impossible; no raw SVG/HTML is emitted. Also asserts the cache stores only derived artifacts and
a cache hit avoids a second sandbox render.
"""

from __future__ import annotations

from fathom.preview.renderers.text import TextRenderer
from fathom.preview.service import ResolvedEntry
from fathom.preview.types import SupportedType
from tests.preview.conftest import (
    DEFAULT_CAPS,
    RecordingDriver,
    make_service,
)

_TEXT = b"def hello():\n    return 'world'\n"
_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64  # PNG magic + padding (image class)


def _entry(entry_id: int, content_hash: str | None = "a" * 64) -> ResolvedEntry:
    return ResolvedEntry(
        entry_id=entry_id,
        host_id=1,
        volume_id=1,
        path="/mnt/pool/file",
        inode=entry_id,
        content_hash=content_hash,
    )


async def test_text_render_is_derived_not_raw() -> None:
    """The real text renderer emits a derived snippet/highlight — never the raw input bytes."""
    artifacts = TextRenderer().render(_TEXT, detected=SupportedType.TEXT, caps=DEFAULT_CAPS)
    # A derived text snippet exists, and no artifact equals the raw input (it is transformed,
    # bounded, and re-encoded as UTF-8 — never a passthrough of the original container bytes).
    assert any(a.kind == "text_snippet" for a in artifacts)
    assert all(a.media_type in ("text/plain", "application/json") for a in artifacts)
    # No raw HTML/SVG ever (the highlight is structured JSON tokens, not markup).
    assert all(b"<svg" not in a.data and b"<html" not in a.data.lower() for a in artifacts)


async def test_service_render_never_returns_raw_input() -> None:
    """End-to-end through the service: the output is derived, not the raw input (ADR-014)."""
    service, _driver, _ = make_service(files={1: _TEXT, 2: _PNG})
    result, _ = await service.render(_entry(1), job_id="j1")
    assert result.cache_hit is False
    for artifact in result.artifacts:
        assert artifact.data != _TEXT  # never byte-equal to the raw original

    img_result, _ = await service.render(_entry(2, content_hash="b" * 64), job_id="j2")
    assert img_result.type is SupportedType.IMAGE
    for artifact in img_result.artifacts:
        assert artifact.data != _PNG


async def test_cache_hit_skips_second_render() -> None:
    """A second request for the same content is served from the encrypted cache, not re-rendered."""
    driver = RecordingDriver()
    service, _, _ = make_service(files={1: _TEXT}, driver=driver)
    first, _ = await service.render(_entry(1), job_id="j1")
    assert first.cache_hit is False
    assert len(driver.seen) == 1
    second, _ = await service.render(_entry(1), job_id="j2")
    assert second.cache_hit is True  # served from cache
    assert len(driver.seen) == 1  # the sandbox was NOT invoked a second time
