"""Shared preview-test fixtures — a fake sandbox driver + file fetcher and a runtime wirer.

The real ``runsc`` sandbox cannot run in CI, so these fakes stand in for the sandbox driver and
the signed single-file pull. The fake driver runs the *real* in-process renderers (text path)
or echoes a derived artifact, but NEVER returns raw input bytes — exactly the contract the route
relies on. ``wire_preview_runtime`` injects a ``PreviewRuntime`` onto an app, mirroring how the
deploy enablement step provisions it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI

from fathom.api.app import create_app
from fathom.api.preview_runtime import PreviewRuntime
from fathom.core import db
from fathom.core.catalogue.models import FsEntryRow, Host, Volume
from fathom.core.settings import Settings
from fathom.preview.cache import EncryptedLruCache
from fathom.preview.service import FileFetcher, PreviewService, ResolvedEntry
from fathom.preview.types import (
    PreviewArtifact,
    PreviewError,
    ResourceCaps,
    SupportedType,
)
from fathom.workers.preview import PreviewQueue


@pytest.fixture
async def preview_settings(tmp_path: Path) -> Settings:
    """Settings with the preview gate ON over a temp SQLite catalogue (default-OFF elsewhere)."""
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        preview_enabled=True,
    )


@pytest.fixture
async def preview_app(preview_settings: Settings) -> AsyncIterator[FastAPI]:
    """A live app over a temp catalogue, lifespan-managed (no preview runtime wired yet)."""
    await db.dispose_engine()
    app = create_app(preview_settings)
    async with LifespanManager(app):
        yield app
    await db.dispose_engine()


@pytest.fixture
async def preview_client(preview_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """An httpx client bound to the live preview app."""
    transport = httpx.ASGITransport(app=preview_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


DEFAULT_CAPS = ResourceCaps(
    cpu=1.0,
    mem_bytes=512 * 1024 * 1024,
    time_s=10.0,
    max_pages=50,
    max_decompressed_bytes=100 * 1024 * 1024,
)


@dataclass(slots=True)
class FakeFetcher:
    """A fake signed single-file pull returning canned raw bytes keyed by entry id."""

    files: Mapping[int, bytes]

    async def fetch(self, entry: ResolvedEntry, *, max_bytes: int) -> bytes:
        raw = self.files.get(entry.entry_id)
        if raw is None:
            raise PreviewError("file unavailable", status_code=502)
        return raw


@dataclass(slots=True)
class RecordingDriver:
    """A fake sandbox driver that emits a DERIVED artifact and records what it was asked to render.

    It NEVER returns the raw input — it re-encodes/derives, exactly as the real sandbox must. The
    recorded ``seen`` lets tests assert the driver was (or was not) invoked, e.g. on a cache hit.
    """

    seen: list[tuple[int, str]] = field(default_factory=list)

    async def run(
        self,
        raw: bytes,
        *,
        detected: SupportedType,
        caps: ResourceCaps,
        job_id: str,
    ) -> list[PreviewArtifact]:
        self.seen.append((len(raw), detected.value))
        # Derive a tiny artifact: a length marker + a transformed prefix — never the raw bytes.
        derived = f"derived:{detected.value}:{len(raw)}".encode()
        return [
            PreviewArtifact(
                kind="text_snippet" if detected is SupportedType.TEXT else "thumbnail",
                media_type="text/plain" if detected is SupportedType.TEXT else "image/webp",
                data=derived,
                meta={"derived": True},
            )
        ]


def make_service(
    *,
    files: Mapping[int, bytes],
    driver: RecordingDriver | None = None,
    cache: EncryptedLruCache | None = None,
    caps: ResourceCaps = DEFAULT_CAPS,
    max_input_bytes: int = 256 * 1024 * 1024,
    cache_ttl_seconds: int = 1800,
) -> tuple[PreviewService, RecordingDriver, EncryptedLruCache]:
    """Build a PreviewService over fakes; return ``(service, driver, cache)`` for assertions."""
    drv = driver or RecordingDriver()
    cch = cache or EncryptedLruCache.from_key_material(
        None, max_entries=8, ttl_seconds=cache_ttl_seconds
    )
    fetcher: FileFetcher = FakeFetcher(files=files)
    service = PreviewService(
        cache=cch,
        driver=drv,
        fetcher=fetcher,
        caps=caps,
        max_input_bytes=max_input_bytes,
        cache_ttl_seconds=cache_ttl_seconds,
    )
    return service, drv, cch


@dataclass(slots=True)
class SeededEntry:
    """The ids of a seeded catalogue entry (host/volume/entry) for scope assertions."""

    entry_id: int
    host_id: int
    volume_id: int


async def seed_entry(
    *,
    host_name: str = "nas-1",
    fingerprint: str = "ab:cd:ef:01",
    mountpoint: str = "/mnt/pool",
    rel: str = "photo.jpg",
    inode: int = 4242,
    full_hash: str | None = None,
    is_dir: bool = False,
) -> SeededEntry:
    """Seed one host/volume/fs_entry row directly; return its ids (for preview + scope tests)."""
    async with db.session_scope() as session:
        host = Host(name=host_name, cert_fingerprint=fingerprint)
        session.add(host)
        await session.flush()
        volume = Volume(
            host_id=host.id,
            mountpoint=mountpoint,
            fs_type="zfs",
            device="tank",
            transport="sata",
        )
        session.add(volume)
        await session.flush()
        entry = FsEntryRow(
            host_id=host.id,
            volume_id=volume.id,
            name=rel.rsplit("/", 1)[-1],
            path=f"{mountpoint}/{rel}",
            depth=1,
            is_dir=is_dir,
            size_logical=100,
            size_on_disk=100,
            inode=inode,
            full_hash=full_hash,
            present=True,
        )
        session.add(entry)
        await session.flush()
        return SeededEntry(entry_id=entry.id, host_id=host.id, volume_id=volume.id)


def wire_preview_runtime(
    app: FastAPI,
    *,
    files: Mapping[int, bytes],
    driver: RecordingDriver | None = None,
    cache: EncryptedLruCache | None = None,
    caps: ResourceCaps = DEFAULT_CAPS,
) -> tuple[RecordingDriver, EncryptedLruCache]:
    """Inject a PreviewRuntime onto ``app.state`` (mirrors deploy enablement); return the fakes."""
    service, drv, cch = make_service(files=files, driver=driver, cache=cache, caps=caps)
    app.state.preview_runtime = PreviewRuntime(service=service, queue=PreviewQueue())
    return drv, cch
