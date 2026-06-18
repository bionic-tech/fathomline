# Migrations (Alembic)

Schema is owned by Alembic in production (ADD 09 §6); the ORM models in
`fathom.core.catalogue.models` are the source of truth for autogeneration.

```bash
# Generate the first revision against a real PostgreSQL (asyncpg URL):
FATHOM_DATABASE_URL=postgresql+psycopg://… uv run alembic revision --autogenerate -m "initial catalogue"
FATHOM_DATABASE_URL=postgresql+psycopg://… uv run alembic upgrade head
```

After autogeneration, hand-edit the initial revision to add the Postgres-only mechanics the
ORM stays agnostic about:

- LIST-partition `fs_entry` by `host_id` (sub-partition by `volume_id`) — ADD 09 §8.
- `text_pattern_ops` index on `fs_entry.path` for prefix subtree scans — ADD 09 §2.

> Dev/test uses `Settings.auto_create_schema` (SQLite) instead of migrations.
