"""Auth/RBAC Alembic migration round-trip on SQLite (ADD 09 §6; test_plan)."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

AUTH_TABLES = {
    "auth_user",
    "auth_role_assignment",
    "auth_session",
    "auth_mfa_enrollment",
    "auth_identity_binding",
}
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'mig.db'}"
    # env.py reads the URL from settings; pin it and clear the cached singleton so the
    # migration runs against this temp DB rather than a settings object built earlier.
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def test_upgrade_creates_auth_tables_and_volume_kind(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    sync_url = db_url.replace("+aiosqlite", "")
    engine = create_engine(sync_url)
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names())
        assert AUTH_TABLES <= tables
        volume_cols = {c["name"] for c in insp.get_columns("volume")}
        assert "kind" in volume_cols
    finally:
        engine.dispose()


def test_downgrade_drops_auth_tables(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    sync_url = db_url.replace("+aiosqlite", "")
    engine = create_engine(sync_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert not (AUTH_TABLES & tables)
    finally:
        engine.dispose()
