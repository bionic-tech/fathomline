"""End-to-end ingest for remote volumes (ADR-029) — the regression these would have caught.

Before the synthetic-mountpoint fix, a remote volume's ``scheme://`` mountpoint failed ingest's
AR-0012 re-vetting (``validate_config_path``), so SFTP/SMB/rclone agents could not push to the
catalogue at all. These tests drive a real ingest of a remote-shaped batch (synthetic POSIX mount
+ display_name + entries anchored under it) and assert it lands, the pretty label persists, and
the tree drill works — i.e. remote volumes now satisfy the same contract as local ones.
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from fathom.agent.config import RemoteBackendConfig
from fathom.backends.remote import synthetic_inode
from fathom.core import db
from fathom.core.catalogue.models import Volume
from tests.api.conftest import FINGERPRINT_HEADER, seed_principal

_CONFIGS = {
    "rclone": RemoteBackendConfig(protocol="rclone", host="gdrive", remote_path="/Backups"),
    "sftp": RemoteBackendConfig(protocol="sftp", host="nas-1", remote_path="/data"),
    "smb": RemoteBackendConfig(protocol="smb", host="nas-1", share="media", remote_path="/data"),
}


def _remote_entry(path: str, *, is_dir: bool, size: int = 0) -> dict:
    # Remote entries carry synthetic ownership (cloud/share has no POSIX uid/gid; AR-027).
    return {
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "is_dir": is_dir,
        "is_symlink": False,
        "size_logical": size,
        "size_on_disk": size,
        "mtime": 1000.0,
        "ctime": 1000.0,
        "uid": -1,
        "gid": -1,
        # Stable per-path synthetic inode (what the real remote backends produce; ADR-029) — so
        # remote entries don't collide on the (host, volume, dev=0, inode) identity.
        "inode": synthetic_inode(path),
        "flags": {"synthetic_owner": True},
    }


def _remote_batch(cfg: RemoteBackendConfig) -> dict:
    mount = cfg.catalogue_mount
    return {
        "host": {"name": "remote-host", "os": "linux", "agent_version": "0.1.0"},
        "volume": {
            "mountpoint": mount,  # synthetic POSIX-absolute (the fix) — not the scheme:// key
            "display_name": cfg.mount_key,  # pretty rclone://… / sftp://… / smb://…
            "fs_type": cfg.protocol,
            "device": "remote",
            "transport": "network",
            "total": 0,
            "used": 0,
            "free": 0,
        },
        "mode": "metadata",
        "entries": [
            _remote_entry(mount, is_dir=True),  # the volume root
            _remote_entry(f"{mount}/sub", is_dir=True),
            _remote_entry(f"{mount}/sub/file.bin", is_dir=False, size=100),
        ],
    }


@pytest.mark.parametrize("proto", ["rclone", "sftp", "smb"])
async def test_remote_volume_ingests_end_to_end(api_client: httpx.AsyncClient, proto: str) -> None:
    cfg = _CONFIGS[proto]
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=_remote_batch(cfg), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["entries_received"] == 3 and body["entries_rejected"] == 0
    volume_id = body["volume_id"]

    # The pretty scheme:// label is persisted as display_name; mountpoint stays synthetic.
    async with db.session_scope() as session:
        volume = (await session.execute(select(Volume).where(Volume.id == volume_id))).scalar_one()
    assert volume.mountpoint == cfg.catalogue_mount
    assert volume.display_name == cfg.mount_key

    # The read API surfaces the label, and the tree drill works off the synthetic mount.
    auth = await seed_principal(username=f"u-{proto}")
    vols = await api_client.get("/api/v1/volumes", headers=auth)
    mine = next(v for v in vols.json() if v["id"] == volume_id)
    assert mine["display_name"] == cfg.mount_key

    tree = await api_client.get(
        "/api/v1/tree",
        params={"volume_id": volume_id, "path": cfg.catalogue_mount},
        headers=auth,
    )
    assert tree.status_code == 200
    assert any(c["path"] == f"{cfg.catalogue_mount}/sub" for c in tree.json())
