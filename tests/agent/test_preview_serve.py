"""Agent-side preview grant-serve — verify a signed grant, read the one file, serve it back.

Uses a real Ed25519 grant signer/verifier + a real temp file (so LocalFileFetcher's O_NOFOLLOW +
inode anchoring runs) and an in-memory nonce ledger; a tiny fake httpx client exercises the
poll → serve cycle (bytes posted on success, an error posted on a bad grant).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.agent.preview_serve import POLL_PATH, SERVE_PATH, PreviewGrantServer, handle_one
from fathom.core.remediation.nonce_store import InMemoryNonceStore
from fathom.preview.grant import (
    FileGrant,
    GrantReplayError,
    GrantSigner,
    GrantVerificationError,
    GrantVerifier,
    SignedFileGrant,
)
from fathom.preview.pull import ClaimedGrant

_KEY_ID = "preview-v1"


def _keypair() -> tuple[GrantSigner, GrantVerifier]:
    priv = Ed25519PrivateKey.generate()
    return GrantSigner(priv, key_id=_KEY_ID), GrantVerifier(priv.public_key(), key_id=_KEY_ID)


def _grant_for(path: str, *, host_id: str = "nas-1", nonce: str = "n" * 16) -> FileGrant:
    now = datetime.now(tz=UTC)
    return FileGrant(
        grant_id="g1",
        entry_id=1,
        host_id=host_id,
        volume_id=1,
        inode=Path(path).stat().st_ino,
        path=path,
        nonce=nonce,
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    )


def _server(verifier: GrantVerifier, *, host_id: str = "nas-1") -> PreviewGrantServer:
    return PreviewGrantServer(verifier=verifier, nonce_store=InMemoryNonceStore(), host_id=host_id)


async def test_serve_reads_and_returns_the_named_file(tmp_path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"the-file-bytes")
    signer, verifier = _keypair()
    signed = signer.sign(_grant_for(str(f)))
    out = await _server(verifier).serve(signed, max_bytes=1000)
    assert out == b"the-file-bytes"


async def test_serve_rejects_a_grant_signed_by_another_key(tmp_path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    signer, _ = _keypair()
    _, other_verifier = _keypair()  # a different key pair → signature won't verify
    signed = signer.sign(_grant_for(str(f)))
    with pytest.raises(GrantVerificationError):
        await _server(other_verifier).serve(signed, max_bytes=1000)


async def test_serve_rejects_a_replayed_grant(tmp_path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    signer, verifier = _keypair()
    server = _server(verifier)  # shares one nonce ledger across both serve calls
    signed = signer.sign(_grant_for(str(f)))
    await server.serve(signed, max_bytes=1000)  # first use consumes the nonce
    with pytest.raises(GrantReplayError):
        await server.serve(signed, max_bytes=1000)  # replay → rejected


async def test_serve_rejects_inode_swap(tmp_path) -> None:
    # The grant names inode N; if the on-disk file no longer has that inode (replaced), the read
    # refuses (LocalFileFetcher's fstat inode anchor) → PreviewError, surfaced as a served error.
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    signer, verifier = _keypair()
    grant = _grant_for(str(f))
    bad = FileGrant(**{**grant.model_dump(), "inode": grant.inode + 99999})
    from fathom.preview.types import PreviewError

    with pytest.raises(PreviewError):
        await _server(verifier).serve(signer.sign(bad), max_bytes=1000)


# --- the poll → serve cycle (fake transport) -------------------------------------------------


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        assert self._payload is not None
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    def __init__(self, poll: _Resp) -> None:
        self._poll = poll
        self.served: list[dict] = []

    async def post(self, path: str, json: dict | None = None) -> _Resp:
        if path == POLL_PATH:
            return self._poll
        if path == SERVE_PATH:
            assert json is not None
            self.served.append(json)
            return _Resp(200)
        raise AssertionError(f"unexpected path {path}")


def _claimed(signed: SignedFileGrant, max_bytes: int = 1000) -> _Resp:
    return _Resp(
        200, ClaimedGrant(signed_grant=signed, max_bytes=max_bytes).model_dump(mode="json")
    )


async def test_handle_one_posts_bytes_on_success(tmp_path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"served-content")
    signer, verifier = _keypair()
    client = _FakeClient(_claimed(signer.sign(_grant_for(str(f)))))
    handled = await handle_one(client, _server(verifier))  # type: ignore[arg-type]
    assert handled is True
    assert len(client.served) == 1
    assert base64.b64decode(client.served[0]["data_b64"]) == b"served-content"


async def test_handle_one_posts_error_on_bad_grant(tmp_path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    signer, _ = _keypair()
    _, other_verifier = _keypair()
    client = _FakeClient(_claimed(signer.sign(_grant_for(str(f)))))
    handled = await handle_one(client, _server(other_verifier))  # type: ignore[arg-type]
    assert handled is True
    assert client.served[0]["error"] is not None
    assert "data_b64" not in client.served[0] or client.served[0].get("data_b64") is None


async def test_handle_one_idle_204_returns_false(tmp_path) -> None:
    _, verifier = _keypair()
    client = _FakeClient(_Resp(204))
    assert await handle_one(client, _server(verifier)) is False  # type: ignore[arg-type]
    assert client.served == []
