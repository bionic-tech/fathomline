"""Tests for the remote backends (storage-backends test_plan: full-bit refusal, re-stat, creds)."""

from __future__ import annotations

import logging

import pytest

from fathom.agent.config import RemoteBackendConfig
from fathom.backends import (
    FullBitUnsupportedError,
    SftpBackend,
    SmbBackend,
    StorageBackend,
)
from fathom.backends.remote import (
    RemoteBackendError,
    docker_secret_provider,
    resolve_creds,
    restat_changed,
    synthetic_inode,
)
from tests.backends.conftest import FakeRemoteTransport

_SMB_CONFIG = RemoteBackendConfig(
    protocol="smb", host="nas.example", share="media", remote_path="/share"
)
_SFTP_CONFIG = RemoteBackendConfig(protocol="sftp", host="nas.example", remote_path="/share")


def test_synthetic_inode_is_stable_distinct_and_positive() -> None:
    # Stable across calls (so re-scans upsert, not duplicate), distinct per path (no identity
    # collisions), and a positive int64 (fits the catalogue column) — ADR-029.
    a = synthetic_inode("/rclone/gdrive/Backups/a.bin")
    assert a == synthetic_inode("/rclone/gdrive/Backups/a.bin")  # stable
    assert a != synthetic_inode("/rclone/gdrive/Backups/b.bin")  # distinct
    assert 0 < a < 2**63


def test_smb_satisfies_protocol() -> None:
    assert isinstance(SmbBackend(_SMB_CONFIG), StorageBackend)


def test_sftp_satisfies_protocol() -> None:
    assert isinstance(SftpBackend(_SFTP_CONFIG), StorageBackend)


def test_smb_requires_smb_protocol() -> None:
    with pytest.raises(ValueError):
        SmbBackend(_SFTP_CONFIG)  # type: ignore[arg-type]


def test_sftp_requires_sftp_protocol() -> None:
    with pytest.raises(ValueError):
        SftpBackend(_SMB_CONFIG)  # type: ignore[arg-type]


# --------------------------------------------------------- the ADD 02 hard rule (regression-named)


async def test_smb_open_for_hash_raises_fullbit_unsupported() -> None:
    backend = SmbBackend(_SMB_CONFIG)
    with pytest.raises(FullBitUnsupportedError):
        await backend.open_for_hash("/share/anything")


async def test_sftp_open_for_hash_raises_fullbit_unsupported() -> None:
    backend = SftpBackend(_SFTP_CONFIG)
    with pytest.raises(FullBitUnsupportedError):
        await backend.open_for_hash("/share/anything")


# --------------------------------------------------------------------- metadata-only re-stat walk


async def test_sftp_walk_is_restat_only_and_skips_symlink(
    fake_remote_transport: FakeRemoteTransport,
) -> None:
    backend = SftpBackend(_SFTP_CONFIG, transport=fake_remote_transport)
    entries = {e.path: e async for e in backend.walk(_SFTP_CONFIG.mount_key)}

    # Every entry came from a listdir (re-stat) call — there is no content-read method to call.
    assert "/share" in fake_remote_transport.listdir_calls
    assert "/share/docs" in fake_remote_transport.listdir_calls
    # The symlink is reported but NOT traversed (its target dir is never listed).
    assert "/share/link" not in fake_remote_transport.listdir_calls
    # Entries are anchored under the synthetic catalogue_mount (ADR-029), not the real remote path.
    assert "/sftp/nas.example/share/link/secret.txt" not in entries
    # A real file under the walked subtree is present, metadata-only (on-disk == logical).
    guide = entries["/sftp/nas.example/share/docs/guide.pdf"]
    assert guide.size_logical == guide.size_on_disk == 4096
    # No real remote inode → a stable, non-zero synthetic (path-derived) so entries don't collide
    # on the catalogue identity (ADR-029).
    assert guide.inode != 0


async def test_sftp_walk_follows_symlink_when_opted_in(
    fake_remote_transport: FakeRemoteTransport,
) -> None:
    backend = SftpBackend(_SFTP_CONFIG, transport=fake_remote_transport)
    entries = {e.path: e async for e in backend.walk(_SFTP_CONFIG.mount_key, follow_symlinks=True)}
    assert "/sftp/nas.example/share/link/secret.txt" in entries


async def test_smb_walk_metadata_only(fake_remote_transport: FakeRemoteTransport) -> None:
    backend = SmbBackend(_SMB_CONFIG, transport=fake_remote_transport)
    entries = {e.path: e async for e in backend.walk(_SMB_CONFIG.mount_key)}
    # Anchored under the synthetic catalogue_mount (ADR-029): /smb/<host>/<share><remote_path>.
    assert "/smb/nas.example/media/share/readme.txt" in entries
    assert fake_remote_transport.listdir_calls  # re-stat path was taken


async def test_remote_is_busy_is_false(fake_remote_transport: FakeRemoteTransport) -> None:
    smb = SmbBackend(_SMB_CONFIG, transport=fake_remote_transport)
    sftp = SftpBackend(_SFTP_CONFIG, transport=fake_remote_transport)
    assert await smb.is_busy() is False
    assert await sftp.is_busy() is False


async def test_remote_volume_info_network_transport(
    fake_remote_transport: FakeRemoteTransport,
) -> None:
    backend = SftpBackend(_SFTP_CONFIG, transport=fake_remote_transport)
    info = await backend.volume_info(_SFTP_CONFIG.mount_key)
    assert info.transport == "network"
    assert info.total == 1000


def test_supports_matches_only_own_mount_key() -> None:
    smb = SmbBackend(_SMB_CONFIG)
    assert smb.supports(_SMB_CONFIG.mount_key) is True
    assert smb.supports("/some/local/path") is False
    assert smb.supports(_SFTP_CONFIG.mount_key) is False


# --------------------------------------------------------------------- credential resolution (010)


def test_creds_resolved_from_secret_backend_count_only_logging(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secrets = {"smb-pass": "s3cr3t-do-not-log"}
    config = RemoteBackendConfig(
        protocol="smb",
        host="nas.example",
        share="media",
        username="alice",
        password_ref="smb-pass",
    )
    backend = SmbBackend(config, secret_provider=secrets.__getitem__)
    with caplog.at_level(logging.INFO):
        creds = backend._creds()
    assert creds.username == "alice"  # username is a plain identity, not resolved via the backend
    assert creds.has_password is True
    # Count-only: the secret VALUE must never appear in any log record.
    assert all("s3cr3t-do-not-log" not in rec.getMessage() for rec in caplog.records)
    assert all("s3cr3t-do-not-log" not in str(rec.__dict__) for rec in caplog.records)


def test_creds_require_provider_when_reference_set() -> None:
    # A secret reference with no provider is a fail-closed error (creds never inline).
    with pytest.raises(RemoteBackendError):
        resolve_creds(
            username=None,
            password_ref="some-ref",
            private_key_ref=None,
            secret_provider=None,
        )


def test_creds_repr_is_redacted() -> None:
    creds = resolve_creds(
        username="bob",
        password_ref="ref",
        private_key_ref=None,
        secret_provider={"ref": "topsecret"}.__getitem__,
    )
    assert "topsecret" not in repr(creds)
    assert "has_password=True" in repr(creds)


def test_docker_secret_provider_rejects_path_traversal() -> None:
    with pytest.raises(RemoteBackendError):
        docker_secret_provider("../../etc/passwd")


def test_docker_secret_provider_reads_named_secret(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pathlib import Path

    import fathom.backends.remote as remote_mod

    secrets_dir = Path(str(tmp_path))
    (secrets_dir / "smb-pass").write_text("hunter2\n", encoding="utf-8")
    monkeypatch.setattr(remote_mod, "_DOCKER_SECRETS_DIR", secrets_dir)
    assert remote_mod.docker_secret_provider("smb-pass") == "hunter2"


def test_docker_secret_provider_missing_secret_raises(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pathlib import Path

    import fathom.backends.remote as remote_mod

    monkeypatch.setattr(remote_mod, "_DOCKER_SECRETS_DIR", Path(str(tmp_path)))
    with pytest.raises(RemoteBackendError):
        remote_mod.docker_secret_provider("nope")


# ------------------------------------------------------------------------ re-stat change feed


def test_restat_changed_detects_new_and_modified() -> None:
    previous = {"/a": 100.0, "/b": 200.0}
    current = [("/a", 100.0), ("/b", 250.0), ("/c", 300.0)]
    assert restat_changed(previous, current) == {"/b", "/c"}


def test_restat_changed_empty_when_unchanged() -> None:
    previous = {"/a": 100.0}
    assert restat_changed(previous, [("/a", 100.0)]) == set()
