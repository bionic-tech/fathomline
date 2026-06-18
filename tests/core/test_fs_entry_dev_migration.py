"""Alembic round-trip for the fs_entry dev-identity migration on SQLite.

``f6c4d8a1b2e7`` adds ``fs_entry.dev`` and widens the agent-identity unique from
``(host_id, volume_id, inode)`` to ``(host_id, volume_id, dev, inode)`` — the fix for the live
cross-dataset bug where ZFS child datasets reuse low inode numbers and collide. Upgrade installs
the dev column + the wider unique, so two rows with the same inode but different dev coexist (and
a true duplicate — same dev+inode — is still rejected). Downgrade restores the inode-only unique
and drops dev. Verified on SQLite via Alembic batch mode for parity with the rest of the suite
(PostgreSQL emits raw ALTER DDL on the partitioned parent — see the migration docstring).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TABLE = "fs_entry"
_IDENTITY_UNIQUE = "uq_fs_entry_identity"
_PRIOR_REVISION = "e5b3c7f2a9d1"


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'fsentrymig.db'}"
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def _seed_host_volume(conn: Connection) -> None:
    conn.execute(text("INSERT INTO host (id, name, cert_fingerprint) VALUES (1, 'h', 'fp')"))
    conn.execute(
        text(
            "INSERT INTO volume (id, host_id, mountpoint, fs_type, device, transport, "
            "total, used, free, updated_at) "
            "VALUES (1, 1, '/mnt/pool', 'zfs', 'tank', 'sata', 0, 0, 0, '2026-06-06')"
        )
    )


# Two fixed, fully-literal statements (no string composition) so there is no SQL-injection vector.
_INSERT_WITHOUT_DEV = text(
    "INSERT INTO fs_entry "
    "(id, host_id, volume_id, name, path, depth, is_dir, is_symlink, "
    "size_logical, size_on_disk, mtime, ctime, uid, gid, inode, flags) "
    "VALUES (:id, 1, 1, 'f', :path, 0, 0, 0, 0, 0, 0, 0, 0, 0, :inode, '{}')"
)
_INSERT_WITH_DEV = text(
    "INSERT INTO fs_entry "
    "(id, host_id, volume_id, name, path, depth, is_dir, is_symlink, "
    "size_logical, size_on_disk, mtime, ctime, uid, gid, inode, flags, dev) "
    "VALUES (:id, 1, 1, 'f', :path, 0, 0, 0, 0, 0, 0, 0, 0, 0, :inode, '{}', :dev)"
)


def _insert_entry(conn: Connection, *, id_: int, inode: int, dev: int, with_dev: bool) -> None:
    """Insert one minimal fs_entry row (raw SQL — exercises the DB constraint, not the ORM)."""
    params: dict[str, object] = {"id": id_, "path": f"/mnt/pool/f{id_}", "inode": inode}
    if with_dev:
        params["dev"] = dev
        conn.execute(_INSERT_WITH_DEV, params)
    else:
        conn.execute(_INSERT_WITHOUT_DEV, params)


def test_upgrade_adds_dev_and_widens_identity(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_TABLE)}
        assert "dev" in columns
        unique_cols = {uc["name"]: uc["column_names"] for uc in insp.get_unique_constraints(_TABLE)}
        assert unique_cols.get(_IDENTITY_UNIQUE) == ["host_id", "volume_id", "dev", "inode"]

        with engine.begin() as conn:
            _seed_host_volume(conn)
            # Same inode, different dev → both allowed (the cross-dataset fix).
            _insert_entry(conn, id_=1, inode=5, dev=64769, with_dev=True)
            _insert_entry(conn, id_=2, inode=5, dev=64770, with_dev=True)
        # Same dev AND inode → still a true duplicate, rejected by the identity unique.
        with pytest.raises(IntegrityError), engine.begin() as conn:
            _insert_entry(conn, id_=3, inode=5, dev=64769, with_dev=True)
    finally:
        engine.dispose()


def test_downgrade_restores_inode_only_identity(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _PRIOR_REVISION)  # one step back: undo just this revision
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_TABLE)}
        assert "dev" not in columns
        unique_cols = {uc["name"]: uc["column_names"] for uc in insp.get_unique_constraints(_TABLE)}
        assert unique_cols.get(_IDENTITY_UNIQUE) == ["host_id", "volume_id", "inode"]

        with engine.begin() as conn:
            _seed_host_volume(conn)
            _insert_entry(conn, id_=1, inode=5, dev=0, with_dev=False)
        # Post-downgrade the identity is inode-only again: a same-inode row is now a duplicate.
        with pytest.raises(IntegrityError), engine.begin() as conn:
            _insert_entry(conn, id_=2, inode=5, dev=0, with_dev=False)
    finally:
        engine.dispose()
