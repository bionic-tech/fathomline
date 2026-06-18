"""``preview_cache_meta`` ORM table (ADD 02 §3; preview-worker data_model_changes).

Tracks **metadata only** for the encrypted derived-artifact cache — it holds **NO raw bytes and
no artifact bytes** (those live encrypted in :class:`~fathom.preview.cache.EncryptedLruCache`).
The row records the content hash, detected type, the size of the encrypted artifact at rest,
created/expiry timestamps (created_at + 30-min TTL), and cache hit/miss accounting. Confidential/
Ephemeral class (data-protection §2): it never persists content excerpts (STRIDE I-8).

Reuses the catalogue ``Base`` so one metadata / one Alembic chain governs the whole schema.
Types are portable (BigInteger / String / DateTime(timezone=True)) so the SQLite test suite stays
green alongside PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from fathom.core.catalogue.models import Base


class PreviewCacheMeta(Base):
    """One cache-entry's metadata — never the artifact bytes (ADR-014; STRIDE I-8).

    ``cache_key`` is the content-hash + render-params key (unique); ``artifact_ref`` is the same
    key the encrypted cache stores the ciphertext under (a *reference*, not the bytes).
    ``artifact_size`` is the size of the **encrypted** artifact at rest. ``expires_at`` is
    ``created_at + ttl`` (default 30 min); a row past it is evicted/ignored. ``hit_count`` /
    ``miss`` track access for the cache accounting (file-mgmt §4.2 hit/miss).
    """

    __tablename__ = "preview_cache_meta"
    __table_args__ = (
        # Backs the eviction/lookup scan (an expiry sweep) and the entry-id history.
        Index("ix_preview_cache_meta_expires_at", "expires_at"),
        Index("ix_preview_cache_meta_cache_key", "cache_key", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    entry_id: Mapped[int] = mapped_column(BigInteger, index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    cache_key: Mapped[str] = mapped_column(String(160))
    artifact_ref: Mapped[str] = mapped_column(String(160))
    type: Mapped[str] = mapped_column(String(16))
    # Size of the ENCRYPTED artifact at rest — never the raw content size (I-8 / data-protection).
    artifact_size: Mapped[int] = mapped_column(BigInteger, default=0)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
