"""Catalogue persistence — the central inventory, snapshots, and rollups (ADD 09).

PostgreSQL/Patroni in production (ADR-003); the ORM layer is kept portable so the unit
suite can run against SQLite. Postgres-only mechanics (LIST partitioning of ``fs_entry``
by ``host_id``) live in Alembic migrations as raw DDL, not in the ORM.
"""

from fathom.core.catalogue.models import (
    Base,
    FsEntryRow,
    Host,
    SizeHistory,
    Snapshot,
    SubtreeRollup,
    Volume,
)

__all__ = [
    "Base",
    "FsEntryRow",
    "Host",
    "SizeHistory",
    "Snapshot",
    "SubtreeRollup",
    "Volume",
]
