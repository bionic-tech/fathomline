"""Full-bit/dedup Alembic migration round-trip on SQLite (fullbit-dedup migrations test).

Upgrade adds the fs_entry hash columns + the (volume_id, full_hash) grouping index and creates
dup_group/dup_member; downgrade removes them. The PostgreSQL partitioned-parent ALTER + partial
propagated index is verified separately on PG16 (see migration docstring); this keeps the SQLite
suite green for parity.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

_REPO_ROOT = Path(__file__).resolve().parents[2]
DUP_TABLES = {"dup_group", "dup_member"}
HASH_COLUMNS = {"partial_hash", "full_hash", "hashed_at"}


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'fbmig.db'}"
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def test_upgrade_adds_hashes_and_dup_tables(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names())
        assert DUP_TABLES <= tables
        fs_cols = {c["name"] for c in insp.get_columns("fs_entry")}
        assert HASH_COLUMNS <= fs_cols
        idx_names = {ix["name"] for ix in insp.get_indexes("fs_entry")}
        assert "ix_fs_entry_volume_full_hash" in idx_names
    finally:
        engine.dispose()


def test_downgrade_removes_fullbit_objects(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "b7e2c1a4d9f0")  # one step back: undo just the fullbit revision
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names())
        assert not (DUP_TABLES & tables)
        fs_cols = {c["name"] for c in insp.get_columns("fs_entry")}
        assert not (HASH_COLUMNS & fs_cols)
    finally:
        engine.dispose()
