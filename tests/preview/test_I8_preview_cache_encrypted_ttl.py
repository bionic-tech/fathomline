"""STRIDE I-8 — preview cache is encrypted at rest, TTL'd, and LRU-bounded (ADR-014).

Named regression gate (STRIDE I-8 / data-protection §3/§4/§7): the cached derived artifact is
encrypted at rest (no plaintext excerpt in the stored ciphertext), evicted at the 30-min TTL, and
evicted under the LRU bound. No raw/plaintext content persists.
"""

from __future__ import annotations

from cryptography.fernet import Fernet

from fathom.preview.cache import EncryptedLruCache, derive_cache_key
from fathom.preview.types import PreviewArtifact, PreviewResult, SupportedType


def _result(marker: str) -> PreviewResult:
    return PreviewResult(
        entry_id=1,
        type=SupportedType.TEXT,
        artifacts=[
            PreviewArtifact(
                kind="text_snippet",
                media_type="text/plain",
                data=marker.encode("utf-8"),
            )
        ],
        sandbox_job_id="job-1",
    )


async def test_cache_stores_no_plaintext_excerpt() -> None:
    """The at-rest ciphertext must not contain the plaintext derived content (I-8)."""
    cache = EncryptedLruCache.from_key_material(None, max_entries=4, ttl_seconds=1800)
    secret = "TOP-SECRET-PREVIEW-EXCERPT"
    await cache.put("k1", _result(secret))
    # Reach into the private store to assert the bytes-at-rest are ciphertext, not plaintext.
    stored = cache._store["k1"].ciphertext
    assert secret.encode("utf-8") not in stored
    # And round-trips back to the same content (so it is genuinely encrypted, not dropped).
    hit = await cache.get("k1")
    assert hit is not None
    assert hit.artifacts[0].data == secret.encode("utf-8")
    assert hit.cache_hit is True


async def test_cache_evicts_at_ttl() -> None:
    """An entry past its TTL is a miss (never serve stale content; data-protection §7)."""
    now = {"t": 1000.0}
    cache = EncryptedLruCache(
        key=Fernet.generate_key(),
        max_entries=4,
        ttl_seconds=10,
        clock=lambda: now["t"],
    )
    await cache.put("k1", _result("x"), ttl_seconds=10)
    assert await cache.get("k1") is not None  # within TTL
    now["t"] = 1011.0  # advance past the 10s TTL
    assert await cache.get("k1") is None  # expired → miss


async def test_cache_lru_bounded() -> None:
    """Past the entry bound the oldest entry is evicted (bounded LRU; whichever evicts first)."""
    cache = EncryptedLruCache.from_key_material(None, max_entries=2, ttl_seconds=1800)
    await cache.put("k1", _result("1"))
    await cache.put("k2", _result("2"))
    await cache.get("k1")  # touch k1 so k2 is now the LRU
    await cache.put("k3", _result("3"))  # over bound → evict LRU (k2)
    assert await cache.get("k2") is None
    assert await cache.get("k1") is not None
    assert await cache.get("k3") is not None


def test_cache_key_is_content_addressed() -> None:
    """The cache key is content-hash + render-params addressed (same bytes → same key)."""
    a = derive_cache_key(content_hash="h" * 64, render_params="v1:pages=50")
    b = derive_cache_key(content_hash="h" * 64, render_params="v1:pages=50")
    c = derive_cache_key(content_hash="g" * 64, render_params="v1:pages=50")
    assert a == b
    assert a != c
