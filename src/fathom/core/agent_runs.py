"""Agent run-outcome recording + latest-run lookup (fleet observability).

The agent reports an :class:`~fathom.api.schemas.AgentRunReport` at end-of-run over the mTLS
boundary; :func:`record_agent_run` resolves the host from the verified cert fingerprint (never the
body — AR-0012), **re-derives** the aggregate outcome and totals from the per-scope data (so an
agent can only describe its own scopes, never forge a fleet verdict), and appends an
:class:`~fathom.core.catalogue.models.AgentRun` row. :func:`latest_run_by_host` backs the Agents
tab's per-host "did the last scan succeed?" view.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.api.schemas import AgentRunReport
from fathom.core.catalogue.models import AgentRun, Host

# Outcome vocabulary (server-derived from the reported per-scope errors).
OUTCOME_OK = "ok"
OUTCOME_PARTIAL = "partial"
OUTCOME_FAILED = "failed"


def _derive_outcome(scopes_total: int, scopes_failed: int) -> str:
    """ok = nothing errored; failed = everything errored / nothing scanned; else partial."""
    if scopes_total == 0 or scopes_failed >= scopes_total:
        return OUTCOME_FAILED
    if scopes_failed > 0:
        return OUTCOME_PARTIAL
    return OUTCOME_OK


async def record_agent_run(
    session: AsyncSession, *, cert_fingerprint: str, report: AgentRunReport
) -> AgentRun | None:
    """Persist one agent run for the host identified by ``cert_fingerprint`` (None if unknown).

    Aggregates are recomputed from ``report.scopes`` — the agent-reported per-scope rows are
    trusted only as a description of that host's own scopes, never as an authoritative aggregate.
    """
    host = (
        await session.execute(select(Host).where(Host.cert_fingerprint == cert_fingerprint))
    ).scalar_one_or_none()
    if host is None:
        # The mTLS boundary already authenticated the caller; an unknown fingerprint has simply
        # never ingested, so there is no host to attach a run to. Not an authz failure.
        return None

    scopes = report.scopes
    scopes_total = len(scopes)
    failed = [s for s in scopes if s.error is not None]
    entries_seen = sum(s.entries_seen for s in scopes)
    rows_changed = sum(s.rows_changed for s in scopes)
    run = AgentRun(
        host_id=host.id,
        started_at=report.started_at,
        finished_at=report.finished_at,
        outcome=_derive_outcome(scopes_total, len(failed)),
        entries_seen=entries_seen,
        rows_changed=rows_changed,
        pushed=report.pushed,
        scopes_total=scopes_total,
        scopes_failed=len(failed),
        finalized=report.finalized,
        # First scope error, truncated to the column width — enough to diagnose from the run row.
        error_summary=(failed[0].error[:1024] if failed and failed[0].error else None),
        agent_version=report.agent_version,
        reported_config=report.reported_config,
    )
    session.add(run)
    # ADR-033 (#9): mirror the effective config onto the host (latest-wins) for the Agents UI. Only
    # when the agent reported one — a pre-ADR-033 agent leaves the existing host.reported_config be.
    if report.reported_config is not None:
        host.reported_config = report.reported_config
    await session.flush()
    return run


async def latest_run_by_host(session: AsyncSession, host_ids: Sequence[int]) -> dict[int, AgentRun]:
    """Return the most recent :class:`AgentRun` per host id (empty for hosts with no run yet)."""
    if not host_ids:
        return {}
    # Per host, the max created_at; then fetch those rows. Two cheap queries beat a window function
    # for SQLite/PG portability and stay correct when two runs share a created_at (max id breaks the
    # tie via the second filter).
    latest_created = (
        select(AgentRun.host_id, func.max(AgentRun.created_at).label("mx"))
        .where(AgentRun.host_id.in_(host_ids))
        .group_by(AgentRun.host_id)
    ).subquery()
    rows = (
        (
            await session.execute(
                select(AgentRun)
                .join(
                    latest_created,
                    (AgentRun.host_id == latest_created.c.host_id)
                    & (AgentRun.created_at == latest_created.c.mx),
                )
                .order_by(AgentRun.host_id, AgentRun.id.desc())
            )
        )
        .scalars()
        .all()
    )
    # On a created_at tie the ORDER BY id DESC means the first row seen per host is the newest.
    out: dict[int, AgentRun] = {}
    for run in rows:
        out.setdefault(run.host_id, run)
    return out
