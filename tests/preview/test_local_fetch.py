"""Single-host LocalFileFetcher tests (ADR-014, single-host topology).

The local fetcher reads exactly the resolved entry's bytes off local disk for a single-host
deployment, with the same hedges as the distributed signed pull: server-resolved path only, no
symlink follow, inode-anchored (refuse a replaced file), and bounded so the service's input cap
still trips. It never decodes — the bytes go only to the sandbox.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fathom.preview.local_fetch import LocalFileFetcher
from fathom.preview.service import ResolvedEntry
from fathom.preview.types import PreviewError


def _entry(path: str, inode: int) -> ResolvedEntry:
    return ResolvedEntry(
        entry_id=1, host_id=1, volume_id=1, path=path, inode=inode, content_hash=None
    )


async def test_reads_local_file_bytes(tmp_path: Path) -> None:
    f = tmp_path / "hello.txt"
    f.write_bytes(b"hello fathom")
    inode = f.stat().st_ino
    data = await LocalFileFetcher().fetch(_entry(str(f), inode), max_bytes=1024)
    assert data == b"hello fathom"


async def test_missing_file_is_404(tmp_path: Path) -> None:
    fetcher = LocalFileFetcher()
    with pytest.raises(PreviewError) as exc:
        await fetcher.fetch(_entry(str(tmp_path / "nope"), 123), max_bytes=1024)
    assert exc.value.status_code == 404


async def test_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "secret"
    target.write_bytes(b"x")
    link = tmp_path / "link"
    link.symlink_to(target)
    fetcher = LocalFileFetcher()
    # O_NOFOLLOW → opening the symlink fails (ELOOP) → unavailable, never follows to the target.
    with pytest.raises(PreviewError) as exc:
        await fetcher.fetch(_entry(str(link), link.stat().st_ino), max_bytes=1024)
    assert exc.value.status_code == 404


async def test_inode_mismatch_is_refused(tmp_path: Path) -> None:
    f = tmp_path / "doc.bin"
    f.write_bytes(b"abc")
    # Catalogue recorded a different inode → the file was replaced since the scan → refuse (409).
    fetcher = LocalFileFetcher()
    with pytest.raises(PreviewError) as exc:
        await fetcher.fetch(_entry(str(f), f.stat().st_ino + 99999), max_bytes=1024)
    assert exc.value.status_code == 409


async def test_reads_one_over_cap_so_service_can_413(tmp_path: Path) -> None:
    f = tmp_path / "big.bin"
    f.write_bytes(b"A" * 5000)
    inode = f.stat().st_ino
    # With a 1000-byte cap the fetcher returns at most cap+1 bytes, so the service sees len>cap.
    data = await LocalFileFetcher().fetch(_entry(str(f), inode), max_bytes=1000)
    assert len(data) == 1001


async def test_single_host_enablement_provisions_runtime(tmp_path: Path) -> None:
    # preview_enabled + preview_local_fetch → the lifespan provisions the runtime with the local
    # fetcher at startup (single-host topology), so the route is live rather than 503.
    from asgi_lifespan import LifespanManager

    from fathom.api.app import create_app
    from fathom.api.preview_runtime import PreviewRuntime
    from fathom.core import db
    from fathom.core.settings import Settings

    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'c.db'}",
        auto_create_schema=True,
        preview_enabled=True,
        preview_local_fetch=True,
    )
    await db.dispose_engine()
    app = create_app(settings)
    async with LifespanManager(app):
        assert isinstance(app.state.preview_runtime, PreviewRuntime)
    await db.dispose_engine()


async def test_default_deployment_does_not_provision_local_runtime(tmp_path: Path) -> None:
    # Default-OFF: without preview_local_fetch the single-host hook never fires (a distributed
    # deployment wires the signed-pull runtime itself), so the route stays fail-closed.
    from asgi_lifespan import LifespanManager

    from fathom.api.app import create_app
    from fathom.core import db
    from fathom.core.settings import Settings

    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'c2.db'}",
        auto_create_schema=True,
        preview_enabled=True,  # enabled, but distributed (no local fetch)
    )
    await db.dispose_engine()
    app = create_app(settings)
    async with LifespanManager(app):
        assert getattr(app.state, "preview_runtime", None) is None
    await db.dispose_engine()


async def test_inode_zero_anchor_is_refused(tmp_path: Path) -> None:
    # A 0 inode is no anchor at all — fail closed rather than read whatever sits at the path.
    f = tmp_path / "f.bin"
    f.write_bytes(b"x")
    with pytest.raises(PreviewError) as exc:
        await LocalFileFetcher().fetch(_entry(str(f), 0), max_bytes=1024)
    assert exc.value.status_code == 409


async def test_content_hash_match_is_read(tmp_path: Path) -> None:
    import blake3

    f = tmp_path / "f.bin"
    f.write_bytes(b"payload-bytes")
    entry = ResolvedEntry(
        entry_id=1,
        host_id=1,
        volume_id=1,
        path=str(f),
        inode=f.stat().st_ino,
        content_hash=blake3.blake3(b"payload-bytes").hexdigest(),
    )
    assert await LocalFileFetcher().fetch(entry, max_bytes=1024) == b"payload-bytes"


async def test_content_hash_mismatch_is_refused(tmp_path: Path) -> None:
    # The catalogue's full hash does not match the bytes on disk (an in-place rewrite that preserved
    # the inode) → refuse, so the inode anchor alone can't be defeated by a same-inode content swap.
    import blake3

    f = tmp_path / "f.bin"
    f.write_bytes(b"actual-on-disk")
    entry = ResolvedEntry(
        entry_id=1,
        host_id=1,
        volume_id=1,
        path=str(f),
        inode=f.stat().st_ino,
        content_hash=blake3.blake3(b"what-the-catalogue-scanned").hexdigest(),
    )
    with pytest.raises(PreviewError) as exc:
        await LocalFileFetcher().fetch(entry, max_bytes=1024)
    assert exc.value.status_code == 409
