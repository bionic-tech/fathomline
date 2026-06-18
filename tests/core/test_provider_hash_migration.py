"""Alembic round-trip for the fs_entry provider_hash migration on SQLite (ADR-028 phase 2).

``d8f1a3c64e2b`` adds the nullable ``provider_hash`` + ``provider_hash_algo`` columns and the
grouping index. Upgrade installs both columns + the index; downgrade drops them. Verified on
SQLite via Alembic batch mode for parity with the suite (PostgreSQL emits raw ALTER DDL + a
partial index on the partitioned parent — see the migration docstring).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TABLE = "fs_entry"
_INDEX = "ix_fs_entry_provider_hash"
_PRIOR_REVISION = "c7e2f4a91b80"


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'provhashmig.db'}"
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def test_upgrade_adds_provider_hash_columns_and_index(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_TABLE)}
        assert {"provider_hash", "provider_hash_algo"} <= columns
        index_names = {ix["name"] for ix in insp.get_indexes(_TABLE)}
        assert _INDEX in index_names
    finally:
        engine.dispose()


def test_downgrade_drops_provider_hash_columns(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _PRIOR_REVISION)  # one step back: undo just this revision
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_TABLE)}
        assert "provider_hash" not in columns and "provider_hash_algo" not in columns
        index_names = {ix["name"] for ix in insp.get_indexes(_TABLE)}
        assert _INDEX not in index_names
    finally:
        engine.dispose()


def test_reupgrade_after_downgrade_is_clean(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _PRIOR_REVISION)
    command.upgrade(cfg, "head")  # must re-apply without error
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        columns = {c["name"] for c in inspect(engine).get_columns(_TABLE)}
        assert {"provider_hash", "provider_hash_algo"} <= columns
    finally:
        engine.dispose()
