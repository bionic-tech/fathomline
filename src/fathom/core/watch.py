"""Proactive watch rules (ADR-040) — re-assess the estate and raise bell alerts.

Pure-ish rules over the catalogue: per-volume **capacity** (used % of total) and **days-to-full**
(linear forecast from `size_history`). Each rule yields a :class:`WatchAlert` carrying a stable
``dedup_key`` so the bell coalesces a repeated condition (a disk that stays 95% full doesn't restack
every tick). The worker (`workers/watch.py`) turns these into bell notifications + outbound sends.
This module does no notification I/O itself, so the rules stay unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.catalogue.models import AgentRun, Host, Volume
from fathom.core.catalogue.notification_meta import (
    CATEGORY_PROBLEM,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
)
from fathom.core.concierge.queries import growth_forecast
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.core.watch")

_SOURCE = "watch"


@dataclass(frozen=True)
class WatchAlert:
    """One alert the watcher will raise into the bell (+ outbound channels)."""

    category: str
    severity: str
    title: str
    body: str
    host_id: int | None
    volume_id: int | None
    dedup_key: str
    source: str = _SOURCE


def _label(volume: Volume) -> str:
    return volume.display_name or volume.mountpoint


def capacity_alert(
    volume: Volume, *, warn_percent: int, critical_percent: int
) -> WatchAlert | None:
    """Raise a capacity alert for a volume over the warn/critical fullness thresholds, else None."""
    if volume.total <= 0:
        return None
    pct = volume.used / volume.total * 100.0
    if pct >= critical_percent:
        severity = SEVERITY_CRITICAL
    elif pct >= warn_percent:
        severity = SEVERITY_WARNING
    else:
        return None
    free_gb = volume.free / (1024**3)
    return WatchAlert(
        category=CATEGORY_PROBLEM,
        severity=severity,
        title=f"{_label(volume)} is {pct:.0f}% full",
        body=f"{free_gb:.1f} GB free on {_label(volume)}.",
        host_id=volume.host_id,
        volume_id=volume.id,
        dedup_key=f"capacity:vol={volume.id}",
    )


def forecast_alert(
    volume: Volume, *, days_to_full: float | None, warn_days: int
) -> WatchAlert | None:
    """Raise a days-to-full alert when a volume fills within ``warn_days`` (else None)."""
    if days_to_full is None or days_to_full > warn_days:
        return None
    return WatchAlert(
        category=CATEGORY_PROBLEM,
        severity=SEVERITY_WARNING,
        title=f"{_label(volume)} will be full in ~{days_to_full:.0f} days",
        body=f"At the current growth rate {_label(volume)} runs out of space in about "
        f"{days_to_full:.0f} days. Plan cleanup or expansion.",
        host_id=volume.host_id,
        volume_id=volume.id,
        dedup_key=f"forecast:vol={volume.id}",
    )


def _age_phrase(hours: float) -> str:
    """A short human age: '14 hours' under a day, else 'N days'."""
    if hours < 48:
        return f"{hours:.0f} hours"
    return f"{hours / 24:.0f} days"


def stale_scan_alert(
    *,
    host_id: int,
    host_name: str,
    last_run_finished: datetime | None,
    now: datetime,
    stale_hours: int,
) -> WatchAlert | None:
    """Raise a problem alert when a host's most recent COMPLETED scan is older than ``stale_hours``.

    A scan that fails before finalizing writes no ``agent_run`` row, so "age since the latest row"
    grows unbounded — that IS the silent-failure signal (it's how nas-1 went 11 days unnoticed). A
    host with no run history yet is not flagged (``last_run_finished`` is None). ``stale_hours<=0``
    disables the rule. Coalesced per host so a persistently-stale host doesn't restack the bell.
    """
    if stale_hours <= 0 or last_run_finished is None:
        return None
    # Postgres (timezone=True) returns aware; SQLite returns naive — normalize so the subtraction
    # never raises offset-naive-vs-aware (the stored value is always UTC).
    finished = last_run_finished
    if finished.tzinfo is None:
        finished = finished.replace(tzinfo=UTC)
    age_hours = (now - finished).total_seconds() / 3600.0
    if age_hours <= stale_hours:
        return None
    age = _age_phrase(age_hours)
    return WatchAlert(
        category=CATEGORY_PROBLEM,
        severity=SEVERITY_CRITICAL if age_hours > stale_hours * 4 else SEVERITY_WARNING,
        title=f"{host_name} hasn't completed a scan in {age}",
        body=(
            f"The last successful scan on {host_name} finished {age} ago (alert threshold "
            f"{stale_hours}h). Its scheduled scan may be failing silently — check the agent and "
            f"the core's ingest health."
        ),
        host_id=host_id,
        volume_id=None,
        dedup_key=f"stale-scan:host={host_id}",
    )


async def evaluate(
    session: AsyncSession, settings: Settings, *, now: datetime | None = None
) -> list[WatchAlert]:
    """Run every watch rule against the current catalogue; return the alerts to raise.

    Capacity is computed from the live ``Volume`` row; the days-to-full forecast reuses the
    concierge's ``growth_forecast`` (best-effort per volume — a forecast failure for one volume
    never suppresses the others' capacity alerts).
    """
    volumes = list((await session.execute(select(Volume))).scalars().all())
    alerts: list[WatchAlert] = []
    for volume in volumes:
        cap = capacity_alert(
            volume,
            warn_percent=settings.watch_capacity_warn_percent,
            critical_percent=settings.watch_capacity_critical_percent,
        )
        if cap is not None:
            alerts.append(cap)
        try:
            forecast = await growth_forecast(
                session, volume_id=volume.id, path=volume.mountpoint, now=now
            )
        except Exception:  # a forecast failure for one volume must not break the sweep
            _log.debug("forecast failed for volume", extra={"volume_id": volume.id})
            forecast = None
        if forecast is not None:
            fa = forecast_alert(
                volume,
                days_to_full=forecast.days_to_full,
                warn_days=settings.watch_days_to_full_warn,
            )
            if fa is not None:
                alerts.append(fa)

    # Per-host stale-scan rule: the most recent COMPLETED scan per host vs the staleness threshold.
    moment = now if now is not None else datetime.now(UTC)
    last_finished = dict(
        (
            await session.execute(
                select(AgentRun.host_id, func.max(AgentRun.finished_at)).group_by(AgentRun.host_id)
            )
        ).all()
    )
    if last_finished:
        hosts = (
            (await session.execute(select(Host).where(Host.id.in_(last_finished)))).scalars().all()
        )
        for host in hosts:
            sa = stale_scan_alert(
                host_id=host.id,
                host_name=host.name,
                last_run_finished=last_finished.get(host.id),
                now=moment,
                stale_hours=settings.watch_scan_stale_hours,
            )
            if sa is not None:
                alerts.append(sa)
    return alerts
