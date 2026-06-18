"""agent config: host.reported_config + host.desired_config + agent_run.reported_config (ADR-033)

Revision ID: b4d7e9f2a1c5
Revises: a2e8f4c1d9b6
Create Date: 2026-06-15 00:00:00.000000

Adds the columns behind ADR-033 (agent self-reported config + operator override):

* ``host.reported_config`` — the EFFECTIVE config the agent last ran with (scan/fullbit scope,
  cross_mounts, write_enabled, throttle), reported at end-of-run; latest-wins, shown in the UI (#9).
* ``host.desired_config`` — the operator's per-host OVERRIDE (partial, MANAGE_AGENTS-set); the agent
  pulls + re-validates it at run start and applies it fail-safe, else keeps its local config (#10).
* ``agent_run.reported_config`` — per-run snapshot of the effective config, for the audit trail.

All three are nullable JSON, default NULL — behaviour-preserving (an agent that never reports leaves
them null; no override means the agent runs its local file unchanged). Chained off ``a2e8f4c1d9b6``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b4d7e9f2a1c5"
down_revision: str | None = "a2e8f4c1d9b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("host") as batch:
        batch.add_column(sa.Column("reported_config", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("desired_config", sa.JSON(), nullable=True))
    with op.batch_alter_table("agent_run") as batch:
        batch.add_column(sa.Column("reported_config", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agent_run") as batch:
        batch.drop_column("reported_config")
    with op.batch_alter_table("host") as batch:
        batch.drop_column("desired_config")
        batch.drop_column("reported_config")
