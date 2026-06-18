"""Alembic round-trip for the agent_run observability table on SQLite.

``e9a2b5d71c34`` creates ``agent_run`` (one row per scan outcome) + its indexes. Upgrade creates
the table; downgrade drops it. Chained off ``d8f1a3c64e2b``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PRIOR_REVISION = "d8f1a3c64e2b"


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'agentrunmig.db'}"
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def test_upgrade_creates_agent_run(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        assert "agent_run" in insp.get_table_names()
        cols = {c["name"] for c in insp.get_columns("agent_run")}
        assert {"host_id", "outcome", "entries_seen", "scopes_failed", "started_at"} <= cols
        index_names = {ix["name"] for ix in insp.get_indexes("agent_run")}
        assert "ix_agent_run_host_created" in index_names
    finally:
        engine.dispose()


def test_downgrade_drops_agent_run(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _PRIOR_REVISION)
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        assert "agent_run" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()
