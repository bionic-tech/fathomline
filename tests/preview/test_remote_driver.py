"""RemoteSandboxDriver + render_request — the core↔worker render split for distributed preview.

Unit-level: a fake transport stands in for the mTLS POST to the worker, and a fake sandbox driver
stands in for the gVisor render, so the wire round-trip (bytes → base64 → bytes, artifacts back)
and the failure mapping (worker unreachable → 502, worker PreviewError propagated) are exercised
without docker.
"""

from __future__ import annotations

import base64

import pytest

from fathom.preview.remote_driver import (
    RemoteSandboxDriver,
    RenderRequest,
    RenderResponse,
    WireArtifact,
    render_request,
)
from fathom.preview.types import PreviewArtifact, PreviewError, ResourceCaps, SupportedType

_CAPS = ResourceCaps(
    cpu=1.0,
    mem_bytes=512 * 1024 * 1024,
    time_s=10.0,
    max_pages=50,
    max_decompressed_bytes=100 * 1024 * 1024,
)


class _FakeDriver:
    """Stands in for RunscSandboxDriver — records the call and returns canned artifacts."""

    def __init__(self, artifacts: list[PreviewArtifact]) -> None:
        self._artifacts = artifacts
        self.seen: dict[str, object] = {}

    async def run(self, raw, *, detected, caps, job_id):  # type: ignore[no-untyped-def]
        self.seen = {"raw": raw, "detected": detected, "job_id": job_id}
        return self._artifacts


async def test_remote_driver_round_trips_through_a_transport() -> None:
    # The worker side, in-process: render_request decodes the bytes, "renders", re-encodes.
    art = PreviewArtifact(
        kind="thumbnail", media_type="image/webp", data=b"\x00\x01derived", meta={"w": 64}
    )
    driver = _FakeDriver([art])

    async def transport(request: RenderRequest) -> RenderResponse:
        # what the worker /render route would do
        assert request.type is SupportedType.IMAGE
        return await render_request(request, driver=driver)

    class _T:
        async def post_render(self, request: RenderRequest) -> RenderResponse:
            return await transport(request)

    remote = RemoteSandboxDriver(transport=_T())
    out = await remote.run(
        b"\xff\xd8\xffraw-jpeg", detected=SupportedType.IMAGE, caps=_CAPS, job_id="job-1"
    )

    # The fake driver saw the exact raw bytes (b64 round-trip is lossless) and job id.
    assert driver.seen["raw"] == b"\xff\xd8\xffraw-jpeg"
    assert driver.seen["job_id"] == "job-1"
    # The derived artifact came back intact (bytes preserved through base64).
    assert len(out) == 1
    assert out[0].kind == "thumbnail" and out[0].data == b"\x00\x01derived"
    assert out[0].meta == {"w": 64}


async def test_remote_driver_maps_unreachable_worker_to_502() -> None:
    class _Broken:
        async def post_render(self, request: RenderRequest) -> RenderResponse:
            raise ConnectionError("worker down")

    remote = RemoteSandboxDriver(transport=_Broken())
    with pytest.raises(PreviewError) as excinfo:
        await remote.run(b"x", detected=SupportedType.TEXT, caps=_CAPS, job_id="j")
    assert excinfo.value.status_code == 502


async def test_remote_driver_propagates_worker_preview_error() -> None:
    # A worker that returns a render error (e.g. a 504 timeout) must surface as-is, not as 502.
    class _Timeout:
        async def post_render(self, request: RenderRequest) -> RenderResponse:
            raise PreviewError("render timed out", status_code=504)

    remote = RemoteSandboxDriver(transport=_Timeout())
    with pytest.raises(PreviewError) as excinfo:
        await remote.run(b"x", detected=SupportedType.TEXT, caps=_CAPS, job_id="j")
    assert excinfo.value.status_code == 504


async def test_render_request_rejects_malformed_payload() -> None:
    req = RenderRequest(job_id="j", type=SupportedType.TEXT, caps=_CAPS, data_b64="not!base64!")
    with pytest.raises(PreviewError) as excinfo:
        await render_request(req, driver=_FakeDriver([]))
    assert excinfo.value.status_code == 400


def test_wire_artifact_round_trip_preserves_bytes() -> None:
    art = PreviewArtifact(kind="text_snippet", media_type="text/plain", data=b"\x00\xff\x10bytes")
    assert WireArtifact.of(art).to_artifact().data == art.data
    assert base64.b64decode(WireArtifact.of(art).data_b64) == art.data
