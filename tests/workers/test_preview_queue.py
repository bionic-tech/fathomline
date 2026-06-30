"""PreviewQueue concurrency-gate behaviour (ADR-014; preview-worker bounded queue).

The ``/preview`` render path runs each sandbox container under a stdlib :class:`asyncio.Semaphore`
gate so unbounded concurrency cannot exhaust the node. These tests pin the contract the route
relies on, with no real sandbox in the loop (the "render" is a plain coroutine the queue runs):

* it caps concurrency to ``max_concurrent`` (renders run serially at 1, in parallel up to the cap);
* it **sheds load** with a 503-class :class:`PreviewError` when no slot frees before
  ``acquire_timeout`` rather than queueing unboundedly (fail-fast under load; EC-PREVIEW-6);
* the slot is always released — even when the render raises — so a failed render never leaks a
  permit and wedges the gate;
* a ``max_concurrent < 1`` is refused at construction.
"""

from __future__ import annotations

import asyncio

import pytest

from fathom.preview.service import ResolvedEntry
from fathom.preview.types import (
    PreviewArtifact,
    PreviewError,
    PreviewResult,
    SupportedType,
)
from fathom.workers.preview import PreviewQueue
from tests.preview.conftest import make_service

_RESULT = PreviewResult(
    entry_id=1,
    type=SupportedType.TEXT,
    artifacts=[PreviewArtifact(kind="text_snippet", media_type="text/plain", data=b"x")],
    cache_hit=False,
    sandbox_job_id="job-1",
)


def _render() -> object:
    """A trivial render coroutine factory returning the canonical ``(result, size)`` tuple."""

    async def run() -> tuple[PreviewResult, int]:
        return _RESULT, 0

    return run


def test_max_concurrent_below_one_refused() -> None:
    """A zero/negative concurrency cap is a config error, refused at construction."""
    with pytest.raises(ValueError):
        PreviewQueue(max_concurrent=0)


async def test_submit_runs_render_and_returns_its_result() -> None:
    queue = PreviewQueue(max_concurrent=1)
    result, size = await queue.submit(_render())
    assert result is _RESULT
    assert size == 0


async def test_sheds_load_with_503_when_no_slot_frees() -> None:
    """A submission that cannot acquire a slot before ``acquire_timeout`` is shed as a 503."""
    queue = PreviewQueue(max_concurrent=1, acquire_timeout=0.05)
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow() -> tuple[PreviewResult, int]:
        started.set()  # the single slot is now held
        await release.wait()
        return _RESULT, 0

    holder = asyncio.create_task(queue.submit(slow))
    await started.wait()  # ensure the only permit is taken before the next submit tries

    with pytest.raises(PreviewError) as excinfo:
        await queue.submit(_render())  # no slot frees within 0.05s → shed
    assert excinfo.value.status_code == 503

    release.set()
    assert (await holder)[0] is _RESULT  # the in-flight render still completes


async def test_runs_serially_under_max_concurrent_one() -> None:
    """With ``max_concurrent=1`` two submissions never overlap (observed concurrency caps at 1)."""
    queue = PreviewQueue(max_concurrent=1, acquire_timeout=5.0)
    active = 0
    peak = 0

    async def tracked() -> tuple[PreviewResult, int]:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return _RESULT, 0

    await asyncio.gather(queue.submit(tracked), queue.submit(tracked))
    assert peak == 1  # strictly serial


async def test_runs_in_parallel_up_to_the_cap() -> None:
    """A ``max_concurrent=2`` queue lets two renders run at once (the cap is the limit, not 1)."""
    queue = PreviewQueue(max_concurrent=2, acquire_timeout=5.0)
    active = 0
    peak = 0
    both_in = asyncio.Event()

    async def tracked() -> tuple[PreviewResult, int]:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == 2:
            both_in.set()
        await both_in.wait()  # hold until both are inside → proves real overlap
        active -= 1
        return _RESULT, 0

    await asyncio.gather(queue.submit(tracked), queue.submit(tracked))
    assert peak == 2


async def test_queue_runs_real_service_render_to_derived_artifact() -> None:
    """enqueue → render → fake-sandbox → artifact: the queue runs a genuine ``PreviewService``.

    The tests above drive the gate with a trivial coroutine; this submits the real
    ``PreviewService.render`` (fake signed-pull fetcher + fake sandbox driver — no gVisor) so the
    worker-layer happy path is exercised: the queue gates a real render and returns its derived
    artifact + the encrypted-at-rest size. The fake sandbox stands in for the runsc container.
    """
    raw = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64  # PNG magic → IMAGE
    entry = ResolvedEntry(
        entry_id=1,
        host_id=1,
        volume_id=1,
        path="/mnt/pool/photo.jpg",
        inode=42,
        content_hash="a" * 64,
    )
    service, driver, _cache = make_service(files={1: raw})
    queue = PreviewQueue(max_concurrent=1)

    result, size = await queue.submit(lambda: service.render(entry, job_id="job-x"))

    assert result.type is SupportedType.IMAGE
    assert result.cache_hit is False
    assert len(result.artifacts) == 1
    artifact = result.artifacts[0]
    assert artifact.kind == "thumbnail"
    assert artifact.data == f"derived:image:{len(raw)}".encode()  # DERIVED, never the raw PNG
    assert artifact.data != raw
    assert driver.seen == [(len(raw), "image")]  # the fake sandbox really ran, once
    assert size > 0  # the derived artifact was encrypted + cached (its at-rest size)


async def test_slot_released_even_when_render_raises() -> None:
    """A render that raises must still free its permit (``finally`` release), not wedge the gate."""
    queue = PreviewQueue(max_concurrent=1, acquire_timeout=0.1)

    async def boom() -> tuple[PreviewResult, int]:
        raise ValueError("render blew up")

    with pytest.raises(ValueError):
        await queue.submit(boom)

    # If the permit had leaked, this submit would shed with a 503 within 0.1s; it must succeed.
    result, _ = await queue.submit(_render())
    assert result is _RESULT
