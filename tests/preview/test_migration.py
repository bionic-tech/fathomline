"""Preview-cache-meta Alembic migration round-trip on SQLite (preview-worker migrations test).

Upgrade creates ``preview_cache_meta`` (metadata-only); downgrade removes it. Chains off the
current head ``c3f1a9b8e210`` with no branch (one head). Keeps the SQLite suite green for parity
with PG16.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TABLE = "preview_cache_meta"
_HEAD_BEFORE = "c3f1a9b8e210"


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'pvmig.db'}"
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def test_upgrade_creates_preview_cache_meta(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        assert _TABLE in set(insp.get_table_names())
        cols = {c["name"] for c in insp.get_columns(_TABLE)}
        assert {
            "entry_id",
            "content_hash",
            "cache_key",
            "artifact_ref",
            "type",
            "artifact_size",
            "expires_at",
        } <= cols
        # The meta table holds NO bytes column — only references/sizes/timestamps (I-8).
        assert "data" not in cols
        idx = {ix["name"] for ix in insp.get_indexes(_TABLE)}
        assert "ix_preview_cache_meta_cache_key" in idx
        assert "ix_preview_cache_meta_expires_at" in idx
    finally:
        engine.dispose()


def test_downgrade_removes_preview_cache_meta(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _HEAD_BEFORE)  # one step back: undo just the preview revision
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        assert _TABLE not in set(insp.get_table_names())
    finally:
        engine.dispose()
