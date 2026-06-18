"""Alembic environment (ADD 09 §6).

Targets the catalogue ``Base.metadata`` for autogeneration and takes the database URL from
Fathom's settings (env-driven, no secrets in the repo). The first revision is generated
against a real PostgreSQL with ``alembic revision --autogenerate``; the Postgres-only
LIST partitioning of ``fs_entry`` (ADD 09 §8) is then added as raw DDL in that revision.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from fathom.auth import models as _auth_models  # noqa: F401 — register auth tables on Base
from fathom.core.catalogue import preview_cache_meta as _preview_meta  # noqa: F401 — register table
from fathom.core.catalogue.models import Base
from fathom.core.remediation import models as _remediation_models  # noqa: F401 — register tables
from fathom.core.settings import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    # Use the async engine directly so the same ``postgresql+asyncpg://`` URL that the app
    # uses also drives migrations — no separate sync driver to install or keep in lockstep.
    connectable = create_async_engine(
        config.get_main_option("sqlalchemy.url"), poolclass=pool.NullPool
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
