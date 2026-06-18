"""Alembic round-trip for the audit prev_hash UNIQUE migration on SQLite (fix (1)).

``e5b3c7f2a9d1`` promotes ``remediation_audit.prev_hash`` from a plain index to a UNIQUE
constraint (the chain-fork arbiter). Upgrade replaces the index with the UNIQUE constraint and a
forked sibling INSERT (same prev_hash) is rejected at the DB; downgrade restores the plain index
and the same insert is allowed again. Verified on SQLite via Alembic batch mode for parity with
the rest of the suite (PostgreSQL emits a plain ALTER — see the migration docstring).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TABLE = "remediation_audit"
_PREV_HASH_UNIQUE = "uq_remediation_audit_prev_hash"
_PREV_HASH_INDEX = "ix_remediation_audit_prev_hash"
_GENESIS = "0" * 64


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    import fathom.core.settings as settings_mod

    url = f"sqlite+aiosqlite:///{tmp_path / 'auditmig.db'}"
    monkeypatch.setenv("FATHOM_DATABASE_URL", url)
    monkeypatch.setattr(settings_mod, "_settings", None)
    return url


def _insert_row(conn: object, *, row_hash: str, prev_hash: str) -> None:
    """Insert one minimal audit row (raw SQL — exercises the DB constraint, not the ORM)."""
    conn.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO remediation_audit "
            "(ts, actor, action, target, before_state, result, prev_hash, row_hash) "
            "VALUES (:ts, :actor, :action, :target, :bs, :result, :prev, :rh)"
        ),
        {
            "ts": "t",
            "actor": "a",
            "action": "x",
            "target": "/t",
            "bs": "{}",
            "result": "ok",
            "prev": prev_hash,
            "rh": row_hash,
        },
    )


def test_upgrade_installs_unique_prev_hash_and_drops_index(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        uniques = {uc["name"] for uc in insp.get_unique_constraints(_TABLE)}
        assert _PREV_HASH_UNIQUE in uniques
        # The plain index is subsumed by the UNIQUE constraint.
        idx_names = {ix["name"] for ix in insp.get_indexes(_TABLE)}
        assert _PREV_HASH_INDEX not in idx_names

        # The constraint actually bites: a forked sibling (same prev_hash) is rejected.
        with engine.begin() as conn:
            _insert_row(conn, row_hash="h1", prev_hash=_GENESIS)
        with pytest.raises(IntegrityError), engine.begin() as conn:
            _insert_row(conn, row_hash="h2", prev_hash=_GENESIS)  # fork → rejected
    finally:
        engine.dispose()


def test_downgrade_restores_plain_index(db_url: str) -> None:
    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "d4a7c2e91b53")  # one step back: undo just this revision
    engine = create_engine(db_url.replace("+aiosqlite", ""))
    try:
        insp = inspect(engine)
        uniques = {uc["name"] for uc in insp.get_unique_constraints(_TABLE)}
        assert _PREV_HASH_UNIQUE not in uniques
        idx_names = {ix["name"] for ix in insp.get_indexes(_TABLE)}
        assert _PREV_HASH_INDEX in idx_names

        # Without the UNIQUE constraint, a duplicate prev_hash is now permitted again.
        with engine.begin() as conn:
            _insert_row(conn, row_hash="h1", prev_hash=_GENESIS)
            _insert_row(conn, row_hash="h2", prev_hash=_GENESIS)  # allowed post-downgrade
    finally:
        engine.dispose()
