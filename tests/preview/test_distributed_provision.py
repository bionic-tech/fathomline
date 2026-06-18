"""HttpRenderTransport + build_distributed_preview — the core-side distributed-preview wiring."""

from __future__ import annotations

import base64

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.api.preview_runtime_dist import PreviewProvisioningError, build_distributed_preview
from fathom.core.settings import Settings
from fathom.preview.pull import PreviewPullQueue
from fathom.preview.remote_driver import HttpRenderTransport, RenderRequest
from fathom.preview.types import PreviewError, ResourceCaps, SupportedType

_CAPS = ResourceCaps(
    cpu=1.0,
    mem_bytes=512 * 1024 * 1024,
    time_s=10.0,
    max_pages=50,
    max_decompressed_bytes=100 * 1024 * 1024,
)


def _signing_pem() -> str:
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


# --- HttpRenderTransport --------------------------------------------------------------------


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        assert self._payload is not None
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)  # type: ignore[arg-type]


class _FakeClient:
    def __init__(self, resp: _Resp) -> None:
        self._resp = resp
        self.sent: dict = {}

    async def post(self, url: str, json: dict | None = None, headers: dict | None = None) -> _Resp:
        self.sent = {"url": url, "json": json, "headers": headers or {}}
        return self._resp


def _req() -> RenderRequest:
    return RenderRequest(
        job_id="j", type=SupportedType.IMAGE, caps=_CAPS, data_b64=base64.b64encode(b"x").decode()
    )


async def test_http_transport_posts_secret_and_parses_response() -> None:
    payload = {
        "artifacts": [
            {
                "kind": "thumbnail",
                "media_type": "image/webp",
                "data_b64": base64.b64encode(b"derived").decode(),
                "meta": {},
            }
        ]
    }
    client = _FakeClient(_Resp(200, payload))
    transport = HttpRenderTransport(client=client, url="https://worker/r", proxy_secret="shh")  # type: ignore[arg-type]
    out = await transport.post_render(_req())
    assert client.sent["headers"]["X-Fathom-Proxy-Secret"] == "shh"
    assert client.sent["url"] == "https://worker/r"
    assert len(out.artifacts) == 1 and out.artifacts[0].kind == "thumbnail"


async def test_http_transport_maps_worker_504_to_preview_error() -> None:
    transport = HttpRenderTransport(
        client=_FakeClient(_Resp(504)),
        url="https://worker/r",
        proxy_secret="shh",  # type: ignore[arg-type]
    )
    with pytest.raises(PreviewError) as excinfo:
        await transport.post_render(_req())
    assert excinfo.value.status_code == 504


# --- build_distributed_preview --------------------------------------------------------------


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "preview_enabled": True,
        "preview_local_fetch": False,
        "preview_grant_signing_key_ref": "grant-key",
        "preview_worker_url": "https://worker/api/v1/preview/render",
        "ingest_proxy_secret": "shared-secret",
    }
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def test_returns_none_when_preview_disabled() -> None:
    assert build_distributed_preview(_settings(preview_enabled=False)) is None


def test_returns_none_for_single_host_local_fetch() -> None:
    assert build_distributed_preview(_settings(preview_local_fetch=True)) is None


def test_returns_none_without_signing_key_or_worker_url() -> None:
    assert build_distributed_preview(_settings(preview_grant_signing_key_ref=None)) is None
    assert build_distributed_preview(_settings(preview_worker_url=None)) is None


def test_assembles_runtime_and_queue_when_configured() -> None:
    pem = _signing_pem()
    client = httpx.AsyncClient()
    try:
        result = build_distributed_preview(
            _settings(),
            secret_provider=lambda ref: pem if ref == "grant-key" else "",
            render_client=client,
        )
    finally:
        pass
    assert result is not None
    runtime, queue = result
    assert isinstance(queue, PreviewPullQueue)
    assert runtime is not None


def test_missing_proxy_secret_is_fail_loud() -> None:
    with pytest.raises(PreviewProvisioningError):
        build_distributed_preview(
            _settings(ingest_proxy_secret=None), secret_provider=lambda ref: _signing_pem()
        )
