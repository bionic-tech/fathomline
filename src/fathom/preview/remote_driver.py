"""Core→worker render transport for distributed preview (ADR-014).

In the distributed topology the **core** hosts the preview route + the file fetch (it has the
catalogue DB and the agent channel), but it cannot run the gVisor sandbox — the core runs on
TrueNAS, where ``runsc`` is not grantable (AR-0002). So the core's :class:`~fathom.preview.service.
PreviewService` is wired with a :class:`RemoteSandboxDriver` in place of
:class:`~fathom.preview.sandbox.RunscSandboxDriver`: it ships the one already-fetched file's raw
bytes to the preview worker (on a gVisor host) over mTLS, the worker runs the real
``RunscSandboxDriver`` in an ephemeral sandbox, and returns **only derived artifacts**.

Raw bytes cross core→worker, but they are never *decoded* in the core (the decode still happens
only inside gVisor on the worker), so the isolation guarantee is unchanged — only the byte hop
differs. :func:`render_request` is the worker side of the same wire; it is the one place that
constructs the real ``RunscSandboxDriver`` (so the E-7 runtime check fails closed on a host that
is not actually running gVisor).
"""

from __future__ import annotations

import base64
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field

from fathom.preview.sandbox import SandboxDriver
from fathom.preview.types import (
    ArtifactKind,
    PreviewArtifact,
    PreviewError,
    ResourceCaps,
    SupportedType,
)


class WireArtifact(BaseModel):
    """A :class:`PreviewArtifact` with its derived bytes base64'd for JSON transport."""

    model_config = ConfigDict(extra="forbid")

    kind: ArtifactKind
    media_type: str = Field(min_length=1, max_length=128)
    data_b64: str
    meta: dict[str, str | int | bool] = Field(default_factory=dict)

    @classmethod
    def of(cls, artifact: PreviewArtifact) -> WireArtifact:
        return cls(
            kind=artifact.kind,
            media_type=artifact.media_type,
            data_b64=base64.b64encode(artifact.data).decode("ascii"),
            meta=artifact.meta,
        )

    def to_artifact(self) -> PreviewArtifact:
        return PreviewArtifact(
            kind=self.kind,
            media_type=self.media_type,
            data=base64.b64decode(self.data_b64),
            meta=self.meta,
        )


class RenderRequest(BaseModel):
    """One render job sent core→worker: the (already-fetched) raw bytes + the detected type + caps.

    The bytes are base64'd; ``type`` is the magic-byte detection the core already did, but the
    sandbox **re-detects** inside the container and never trusts this hint (defence in depth).
    """

    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(min_length=1, max_length=256)
    type: SupportedType
    caps: ResourceCaps
    data_b64: str = Field(min_length=1)


class RenderResponse(BaseModel):
    """The worker's reply: derived artifacts only (never the raw bytes back)."""

    model_config = ConfigDict(extra="forbid")

    artifacts: list[WireArtifact]


class RenderTransport(Protocol):
    """Ships a :class:`RenderRequest` to the worker and returns its :class:`RenderResponse`.

    The production implementation is an mTLS HTTP POST to the worker's ``/render`` route; it is a
    protocol so :class:`RemoteSandboxDriver` is unit-testable with an in-process fake.
    """

    async def post_render(self, request: RenderRequest) -> RenderResponse: ...


class RemoteSandboxDriver:
    """A :class:`~fathom.preview.sandbox.SandboxDriver` that renders on a remote gVisor worker.

    Satisfies the same protocol as ``RunscSandboxDriver`` so ``PreviewService`` is unchanged; it
    just forwards the bytes to the worker instead of spawning a local container.
    """

    def __init__(self, *, transport: RenderTransport) -> None:
        self._transport = transport

    async def run(
        self,
        raw: bytes,
        *,
        detected: SupportedType,
        caps: ResourceCaps,
        job_id: str,
    ) -> list[PreviewArtifact]:
        request = RenderRequest(
            job_id=job_id,
            type=detected,
            caps=caps,
            data_b64=base64.b64encode(raw).decode("ascii"),
        )
        try:
            response = await self._transport.post_render(request)
        except PreviewError:
            raise  # already a sanitised render error (e.g. the worker timed out → 504)
        except Exception as exc:  # transport/connection failure → the worker is unreachable
            raise PreviewError("preview render worker unreachable", status_code=502) from exc
        return [wire.to_artifact() for wire in response.artifacts]


class HttpRenderTransport:
    """Production :class:`RenderTransport`: an mTLS HTTP POST to the worker's ``/render`` route.

    The core authenticates to the worker with the shared ``X-Fathom-Proxy-Secret`` (the same secret
    the mTLS proxy stamps), so a request that did not come from the core is refused at the worker. A
    worker 504 (render timed out) is surfaced as a :class:`PreviewError` 504; any other transport
    failure bubbles to :class:`RemoteSandboxDriver`, which maps it to a 502.
    """

    def __init__(self, *, client: httpx.AsyncClient, url: str, proxy_secret: str) -> None:
        self._client = client
        self._url = url
        self._secret = proxy_secret

    async def post_render(self, request: RenderRequest) -> RenderResponse:
        resp = await self._client.post(
            self._url,
            json=request.model_dump(mode="json"),
            headers={"X-Fathom-Proxy-Secret": self._secret},
        )
        if resp.status_code == 504:
            raise PreviewError("preview render timed out on the worker", status_code=504)
        if resp.status_code >= 500:
            # A worker-SIDE failure (e.g. an E-7 gVisor misconfig → 500) — distinct from an
            # unreachable worker (a transport exception, mapped to 502 in RemoteSandboxDriver). Name
            # the upstream status so the operator sees the worker faulted, not that it was down.
            raise PreviewError(f"preview worker returned HTTP {resp.status_code}", status_code=502)
        resp.raise_for_status()  # any 4xx (e.g. 401 bad secret) → HTTPStatusError → 502 upstream
        return RenderResponse.model_validate(resp.json())


async def render_request(request: RenderRequest, *, driver: SandboxDriver) -> RenderResponse:
    """Worker side of the wire: decode the bytes, run the real gVisor render, return artifacts.

    The worker route passes a real ``RunscSandboxDriver`` here, so the E-7 runtime check
    (``runtime must be 'runsc'``) fails closed at that construction on any host not actually
    running gVisor. ``data_b64`` decode errors surface as a 400-class :class:`PreviewError`.
    """
    try:
        raw = base64.b64decode(request.data_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise PreviewError("malformed render payload", status_code=400) from exc
    artifacts = await driver.run(
        raw, detected=request.type, caps=request.caps, job_id=request.job_id
    )
    return RenderResponse(artifacts=[WireArtifact.of(a) for a in artifacts])
