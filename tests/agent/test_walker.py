"""Tests for the metadata scan orchestrator (ADD 02 §Mode 1)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from fathom.agent.config import ThrottleProfile
from fathom.agent.reader import (
    AcknowledgementRequired,
    LoadSupervisor,
    MetadataScanner,
    WarningAck,
)
from fathom.agent.staging import StagingStore
from fathom.backends import PosixBackend


def _supervisor() -> LoadSupervisor:
    throttle = ThrottleProfile.model_validate(
        {
            "pause_when": {"load1_above": 6.0, "iowait_above_percent": 25},
            "resume_when": {"load1_below": 3.0},
        }
    )
    # Load always low → never pauses, deterministic test.
    return LoadSupervisor(throttle, load1_provider=lambda: 0.1)


def _ack(target: str) -> WarningAck:
    return WarningAck(
        operator="mo", acknowledged_at=datetime.now(tz=UTC), target=target, mode="metadata"
    )


def _scanner(tmp_path: Path) -> tuple[MetadataScanner, StagingStore]:
    store = StagingStore(tmp_path / "staging.sqlite")
    scanner = MetadataScanner(
        backend=PosixBackend(walk_concurrency=2),
        staging=store,
        supervisor=_supervisor(),
        host_id="nas-1",
        batch_size=2,  # force multiple flushes over the fixture tree
    )
    return scanner, store


async def test_scan_requires_acknowledgement(fixture_tree: Path, tmp_path: Path) -> None:
    scanner, store = _scanner(tmp_path)
    with store:
        with pytest.raises(AcknowledgementRequired):
            await scanner.scan(str(fixture_tree))


async def test_scan_stages_entries(fixture_tree: Path, tmp_path: Path) -> None:
    scanner, store = _scanner(tmp_path)
    with store:
        result = await scanner.scan(str(fixture_tree), warning_ack=_ack(str(fixture_tree)))
        assert result.entries_seen >= 7
        assert result.rows_changed == result.entries_seen  # first scan: everything is new
        assert store.count_unpushed() == result.rows_changed
        assert result.volume.mountpoint


async def test_rescan_is_idempotent(fixture_tree: Path, tmp_path: Path) -> None:
    scanner, store = _scanner(tmp_path)
    with store:
        first = await scanner.scan(str(fixture_tree), warning_ack=_ack(str(fixture_tree)))
        second = await scanner.scan(str(fixture_tree), warning_ack=_ack(str(fixture_tree)))
        assert second.entries_seen == first.entries_seen
        assert second.rows_changed == 0  # nothing changed → no duplicate staging


async def test_acknowledgement_persisted(fixture_tree: Path, tmp_path: Path) -> None:
    scanner, store = _scanner(tmp_path)
    with store:
        result = await scanner.scan(str(fixture_tree), warning_ack=_ack(str(fixture_tree)))
        row = store._conn.execute(
            "SELECT warning_ack FROM scan_run WHERE id = ?", (result.run_id,)
        ).fetchone()
        assert row["warning_ack"] is not None
        assert "mo" in row["warning_ack"]
