"""Incremental change-feed Alembic migration round-trip on SQLite (incremental test_plan).

Upgrade adds ``fs_entry.present``/``removed_at`` (+ the partial 'removed' index),
``volume.change_log_enabled``, and the ``change_log`` table; downgrade removes them. The
PostgreSQL partitioned-parent ALTER (propagating to every partition) + the partial
``WHERE present = false`` index are verified separately on PG16 (see migration docstring); this
keeps the SQLite suite green for schema parity, chained linearly off the fullbit head.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FULLBIT_HEAD = "52044159af8a"
FS_COLUMNS = {"present", "removed_at"}


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'incrmig.db'}"
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def test_upgrade_adds_presence_markers_and_change_log(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names())
        assert "change_log" in tables
        fs_cols = {c["name"] for c in insp.get_columns("fs_entry")}
        assert FS_COLUMNS <= fs_cols
        vol_cols = {c["name"] for c in insp.get_columns("volume")}
        assert "change_log_enabled" in vol_cols
        fs_idx = {ix["name"] for ix in insp.get_indexes("fs_entry")}
        assert "ix_fs_entry_removed" in fs_idx
        cl_idx = {ix["name"] for ix in insp.get_indexes("change_log")}
        assert "ix_change_log_volume_ts" in cl_idx
    finally:
        engine.dispose()


def test_downgrade_removes_incremental_objects(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _FULLBIT_HEAD)  # one step back: undo just the incremental revision
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names())
        assert "change_log" not in tables
        fs_cols = {c["name"] for c in insp.get_columns("fs_entry")}
        assert not (FS_COLUMNS & fs_cols)
        vol_cols = {c["name"] for c in insp.get_columns("volume")}
        assert "change_log_enabled" not in vol_cols
    finally:
        engine.dispose()
