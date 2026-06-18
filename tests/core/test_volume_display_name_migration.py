"""Alembic round-trip for the volume.display_name migration on SQLite (ADR-029)."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PRIOR_REVISION = "e9a2b5d71c34"


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'voldnmig.db'}"
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def test_upgrade_adds_display_name(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        cols = {c["name"] for c in inspect(engine).get_columns("volume")}
        assert "display_name" in cols
    finally:
        engine.dispose()


def test_downgrade_drops_display_name(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _PRIOR_REVISION)
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        cols = {c["name"] for c in inspect(engine).get_columns("volume")}
        assert "display_name" not in cols
    finally:
        engine.dispose()
