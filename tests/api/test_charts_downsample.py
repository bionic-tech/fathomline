"""Unit tests for server-side growth-series downsampling (ui-viewer, frontend ADD §10)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fathom.core.query_charts import GrowthPoint, _downsample


def _point(minute: int, size: int) -> GrowthPoint:
    return GrowthPoint(
        ts=datetime(2026, 1, 1, 0, 0, tzinfo=UTC) + timedelta(minutes=minute),
        total_size_logical=size,
        total_size_on_disk=size,
        file_count=1,
    )


def test_downsample_noop_when_under_bucket_count() -> None:
    points = [_point(i, i) for i in range(3)]
    assert _downsample(points, buckets=10) == points


def test_downsample_caps_to_bucket_count() -> None:
    points = [_point(i, i) for i in range(100)]
    out = _downsample(points, buckets=10)
    assert len(out) <= 10
    # Endpoints preserved (last sample of the last slice is the final point).
    assert out[-1] == points[-1]


def test_downsample_keeps_last_sample_per_slice() -> None:
    # 4 points over a 3-minute span, 2 buckets → first half {0,1}, second half {2,3};
    # last-in-window sampling keeps point[1] and point[3].
    points = [_point(i, i * 10) for i in range(4)]
    out = _downsample(points, buckets=2)
    assert [p.total_size_logical for p in out] == [10, 30]


def test_downsample_empty() -> None:
    assert _downsample([], buckets=5) == []


def test_downsample_single_timestamp_collapses() -> None:
    # All points share one timestamp (zero span) → a single representative point.
    points = [_point(0, s) for s in (10, 20, 30)]
    out = _downsample(points, buckets=2)
    assert len(out) == 1
