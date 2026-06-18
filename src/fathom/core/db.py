"""Async database engine & session wiring (ADR-003).

Production points at PostgreSQL/Patroni (``postgresql+asyncpg://``) behind PGBouncer; the
default URL is an in-process SQLite for dev/test. The engine is created lazily so importing
this module never opens a connection.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from fathom.core.settings import Settings, get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(settings: Settings | None = None) -> AsyncEngine:
    """Create (or return) the process-wide async engine."""
    global _engine, _sessionmaker
    if _engine is None:
        cfg = settings or get_settings()
        _engine = create_async_engine(cfg.database_url, echo=cfg.db_echo, future=True)
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the session factory, initialising the engine on first use."""
    if _sessionmaker is None:
        init_engine()
    assert _sessionmaker is not None  # noqa: S101 — init_engine guarantees it
    return _sessionmaker


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Yield a session in a transaction, committing on success and rolling back on error."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Dispose the engine (test teardown / shutdown)."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None
