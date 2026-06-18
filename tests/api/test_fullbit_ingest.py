"""Full-bit ingest tests — hashes persist on a fullbit batch, NULL on metadata (fullbit-dedup).

Asserts the data_model_changes contract: a ``mode='fullbit'`` batch writes
``partial_hash``/``full_hash``/``hashed_at`` onto the fs_entry row; a ``mode='metadata'`` batch
leaves them untouched; and a malformed (non-64-hex) hash is rejected at the schema boundary.
"""

from __future__ import annotations

import httpx
from sqlalchemy import select

from fathom.core import db
from fathom.core.catalogue.models import FsEntryRow
from tests.api.conftest import FINGERPRINT_HEADER, batch

_FULL = "a" * 64
_PARTIAL = "b" * 64


def _fullbit_entry(mount: str, rel: str, inode: int, *, size: int, full: str | None) -> dict:
    path = f"{mount}/{rel}"
    entry = {
        "path": path,
        "name": rel.rsplit("/", 1)[-1],
        "is_dir": False,
        "is_symlink": False,
        "size_logical": size,
        "size_on_disk": size,
        "mtime": 1000.0,
        "ctime": 1000.0,
        "uid": 0,
        "gid": 0,
        "inode": inode,
        "flags": {},
    }
    if full is not None:
        entry["partial_hash"] = _PARTIAL
        entry["full_hash"] = full
    return entry


async def _row_for(volume_id: int, inode: int) -> FsEntryRow:
    async with db.session_scope() as session:
        return (
            await session.execute(
                select(FsEntryRow).where(
                    FsEntryRow.volume_id == volume_id, FsEntryRow.inode == inode
                )
            )
        ).scalar_one()


async def test_fullbit_batch_persists_hashes(api_client: httpx.AsyncClient) -> None:
    body = batch(
        mode="fullbit",
        entries=[_fullbit_entry("/mnt/pool", "movies/a.mkv", 3, size=100, full=_FULL)],
    )
    resp = await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200
    row = await _row_for(resp.json()["volume_id"], 3)
    assert row.full_hash == _FULL
    assert row.partial_hash == _PARTIAL
    assert row.hashed_at is not None  # server-stamped


async def test_metadata_batch_leaves_hashes_null(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200
    row = await _row_for(resp.json()["volume_id"], 3)
    assert row.full_hash is None
    assert row.partial_hash is None
    assert row.hashed_at is None


async def test_metadata_then_fullbit_sets_hash_without_losing_it(
    api_client: httpx.AsyncClient,
) -> None:
    # First a metadata pass (NULL hashes), then a fullbit pass on the same inode → hash set.
    meta = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    volume_id = meta.json()["volume_id"]
    body = batch(
        mode="fullbit",
        entries=[_fullbit_entry("/mnt/pool", "movies/a.mkv", 3, size=100, full=_FULL)],
    )
    resp = await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200
    row = await _row_for(volume_id, 3)
    assert row.full_hash == _FULL  # fullbit upsert sets the hash even though mtime/size unchanged


async def test_malformed_hash_rejected_at_boundary(api_client: httpx.AsyncClient) -> None:
    body = batch(
        mode="fullbit",
        entries=[_fullbit_entry("/mnt/pool", "movies/a.mkv", 3, size=100, full="NOTHEX")],
    )
    resp = await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 422  # Pydantic pattern rejects non-64-hex
