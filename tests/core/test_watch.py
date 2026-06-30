"""Proactive watch rule tests (ADR-040) — capacity + days-to-full + the evaluate sweep.

Pure rules are tested directly; ``evaluate`` runs against a temp catalogue with a near-full and a
healthy volume and must alert on only the full one, with a stable per-volume dedup key.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from fathom.core import db, watch
from fathom.core.catalogue.models import AgentRun, Base, Host, Volume
from fathom.core.settings import Settings


def _vol(**kw: object) -> Volume:
    base: dict[str, object] = {
        "id": 1,
        "host_id": 1,
        "mountpoint": "/mnt/pool",
        "fs_type": "zfs",
        "device": "tank",
        "transport": "sata",
        "total": 100,
        "used": 50,
        "free": 50,
    }
    base.update(kw)
    return Volume(**base)


def test_capacity_warning_and_critical() -> None:
    warn = watch.capacity_alert(_vol(used=92, free=8), warn_percent=90, critical_percent=97)
    assert warn is not None and warn.severity == "warning"
    crit = watch.capacity_alert(_vol(used=98, free=2), warn_percent=90, critical_percent=97)
    assert crit is not None and crit.severity == "critical"
    assert crit.dedup_key == "capacity:vol=1"


def test_capacity_below_threshold_is_none() -> None:
    assert (
        watch.capacity_alert(_vol(used=50, free=50), warn_percent=90, critical_percent=97) is None
    )


def test_capacity_zero_total_is_none() -> None:
    assert (
        watch.capacity_alert(_vol(total=0, used=0, free=0), warn_percent=90, critical_percent=97)
        is None
    )


def test_forecast_alert_within_horizon() -> None:
    vol = _vol()
    assert watch.forecast_alert(vol, days_to_full=5.0, warn_days=14) is not None
    assert watch.forecast_alert(vol, days_to_full=40.0, warn_days=14) is None
    assert watch.forecast_alert(vol, days_to_full=None, warn_days=14) is None


def test_stale_scan_alert_rules() -> None:
    now = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)

    def sa(hrs_ago: float | None, stale_hours: int = 36) -> watch.WatchAlert | None:
        return watch.stale_scan_alert(
            host_id=1,
            host_name="nas-1",
            last_run_finished=None if hrs_ago is None else now - timedelta(hours=hrs_ago),
            now=now,
            stale_hours=stale_hours,
        )

    assert sa(10) is None  # within threshold → quiet
    warn = sa(50)  # past 36h → warning
    assert warn is not None and warn.severity == "warning"
    assert warn.dedup_key == "stale-scan:host=1" and "hasn't completed a scan" in warn.title
    crit = sa(36 * 5)  # more than 4x the threshold -> critical
    assert crit is not None and crit.severity == "critical"
    assert sa(None) is None  # no run history yet → not flagged
    assert sa(9999, stale_hours=0) is None  # rule disabled


async def test_evaluate_flags_a_stale_host_scan(catalogue: None) -> None:
    # Give the catalogue host a last completed run 5 days ago → evaluate() should add a stale-scan
    # alert (alongside the capacity one from the 96%-full volume).
    async with db.session_scope() as session:
        host = (await session.execute(select(Host))).scalars().first()
        assert host is not None
        old = datetime.now(UTC) - timedelta(days=5)
        session.add(
            AgentRun(
                host_id=host.id, started_at=old, finished_at=old, outcome="ok", created_at=old
            )
        )
    async with db.session_scope() as session:
        alerts = await watch.evaluate(session, Settings(watch_scan_stale_hours=36))
    stale = [a for a in alerts if a.dedup_key.startswith("stale-scan:")]
    assert len(stale) == 1
    assert stale[0].host_id == host.id and "days" in stale[0].title


@pytest.fixture
async def catalogue(tmp_path: Path) -> AsyncIterator[None]:
    await db.dispose_engine()
    engine = db.init_engine(Settings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'c.db'}"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with db.session_scope() as session:
        host = Host(name="nas-1", cert_fingerprint="fp")
        session.add(host)
        await session.flush()
        session.add_all(
            [
                Volume(
                    host_id=host.id,
                    mountpoint="/mnt/full",
                    fs_type="zfs",
                    device="tank",
                    transport="sata",
                    total=100,
                    used=96,
                    free=4,
                ),
                Volume(
                    host_id=host.id,
                    mountpoint="/mnt/healthy",
                    fs_type="zfs",
                    device="tank2",
                    transport="sata",
                    total=100,
                    used=10,
                    free=90,
                ),
            ]
        )
    yield
    await db.dispose_engine()


async def test_evaluate_alerts_only_the_full_volume(catalogue: None) -> None:
    settings = Settings(watch_capacity_warn_percent=90, watch_capacity_critical_percent=97)
    async with db.session_scope() as session:
        alerts = await watch.evaluate(session, settings)
    # Only the 96%-full volume trips (warning); the healthy one is silent; no size_history → no
    # forecast alerts.
    assert len(alerts) == 1
    assert alerts[0].severity == "warning"
    assert "/mnt/full" in alerts[0].title
