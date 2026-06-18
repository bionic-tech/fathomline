"""Agent run-outcome recording + latest-run lookup + report builder (observability)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.agent.runner import AgentRunSummary, ScopeOutcome, build_run_report
from fathom.api.schemas import AgentRunReport
from fathom.core.agent_runs import (
    OUTCOME_FAILED,
    OUTCOME_OK,
    OUTCOME_PARTIAL,
    _derive_outcome,
    latest_run_by_host,
    record_agent_run,
)
from fathom.core.catalogue.models import Base, Host


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


@pytest.mark.parametrize(
    ("total", "failed", "expected"),
    [
        (3, 0, OUTCOME_OK),
        (3, 1, OUTCOME_PARTIAL),
        (3, 3, OUTCOME_FAILED),
        (0, 0, OUTCOME_FAILED),  # nothing scanned is a failed run, not a silent "ok"
    ],
)
def test_derive_outcome(total: int, failed: int, expected: str) -> None:
    assert _derive_outcome(total, failed) == expected


def _report(*scopes: tuple[str, int, int, str | None]) -> AgentRunReport:
    now = datetime(2026, 6, 11, tzinfo=UTC)
    return AgentRunReport(
        started_at=now,
        finished_at=now,
        pushed=10,
        finalized=2,
        agent_version="0.1.0",
        scopes=[
            {"root": r, "entries_seen": e, "rows_changed": c, "error": err}
            for (r, e, c, err) in scopes
        ],
    )


async def test_record_derives_partial_and_aggregates(session: AsyncSession) -> None:
    session.add(Host(id=1, name="nas-1", cert_fingerprint="fp1"))
    await session.flush()
    run = await record_agent_run(
        session,
        cert_fingerprint="fp1",
        report=_report(("/a", 100, 5, None), ("/b", 0, 0, "permission denied")),
    )
    assert run is not None
    assert run.outcome == OUTCOME_PARTIAL
    assert run.entries_seen == 100 and run.rows_changed == 5
    assert run.scopes_total == 2 and run.scopes_failed == 1
    assert run.error_summary == "permission denied"  # first scope error, surfaced for diagnosis
    assert run.pushed == 10 and run.finalized == 2 and run.agent_version == "0.1.0"


async def test_record_unknown_fingerprint_is_noop(session: AsyncSession) -> None:
    assert await record_agent_run(session, cert_fingerprint="nope", report=_report()) is None


async def test_latest_run_returns_most_recent(session: AsyncSession) -> None:
    session.add(Host(id=1, name="nas-1", cert_fingerprint="fp1"))
    await session.flush()
    await record_agent_run(session, cert_fingerprint="fp1", report=_report(("/a", 1, 0, None)))
    await record_agent_run(session, cert_fingerprint="fp1", report=_report(("/a", 999, 0, None)))
    latest = await latest_run_by_host(session, [1])
    assert latest[1].entries_seen == 999  # the second (newest) run wins
    assert await latest_run_by_host(session, []) == {}


def test_build_run_report_shape_round_trips_through_schema() -> None:
    now = datetime(2026, 6, 11, tzinfo=UTC)
    summary = AgentRunSummary(
        host_id="nas-1",
        scopes=[ScopeOutcome("/a", 100, 5), ScopeOutcome("/b", 0, 0, error="boom")],
        pushed=7,
        finalized=1,
    )
    body = build_run_report(summary, started_at=now, finished_at=now, agent_version="0.1.0")
    # The builder's body must validate as the wire schema (agent → core contract).
    report = AgentRunReport.model_validate(body)
    assert len(report.scopes) == 2
    assert report.scopes[1].error == "boom"
    assert report.pushed == 7 and report.agent_version == "0.1.0"
