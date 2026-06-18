"""Agent-side preview grant-serve loop (ADR-014; distributed preview) — read-only.

Mirrors the remediation listen loop (:mod:`fathom.agent.actor.listen`) but for the preview pull:
the agent long-polls core for a signed :class:`~fathom.preview.grant.FileGrant` scoped to its host,
verifies it fail-closed (signature → expiry → host scope → single-use nonce), reads exactly the one
file the grant names (``O_NOFOLLOW`` + inode-anchored + bounded, via
:class:`~fathom.preview.local_fetch.LocalFileFetcher` — never a path the grant could be widened to),
and serves the bytes back. It is **read-only**: it does NOT require ``write_enabled`` /
``quarantine_dir`` (the remediation gates), only a pinned core grant public key
(``preview_grant_pubkey_ref``) — absent which the loop never starts (default-off).

This is the ADR-014 review surface: it reintroduces a read of agent-side file content. Every grant
is Ed25519-signed by the pinned core key, single-use (durable :class:`SqliteNonceStore`),
host-scoped, and TTL-bounded; a grant that fails any check (tampered / replayed / expired /
out-of-scope / unreadable) is dropped — served back as an error with no further FS access.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from fathom.agent.config import AgentConfig
from fathom.agent.transport.push import mtls_client
from fathom.core.remediation.nonce_store import SqliteNonceStore
from fathom.core.remediation.signing import NonceStore
from fathom.logging import get_logger
from fathom.preview.grant import (
    GrantReplayError,
    GrantVerificationError,
    GrantVerifier,
    SignedFileGrant,
    verify_grant,
)
from fathom.preview.local_fetch import LocalFileFetcher
from fathom.preview.pull import ClaimedGrant, ServeRequest
from fathom.preview.service import FileFetcher, ResolvedEntry
from fathom.preview.types import PreviewError

_log = get_logger("fathom.agent.preview_serve")

SecretProvider = Callable[[str], str]

POLL_PATH = "/api/v1/agents/preview-grants/poll"
SERVE_PATH = "/api/v1/agents/preview-grants/serve"
# The client read timeout must exceed core's long-poll window (~25s) so a parked poll is not torn
# down mid-wait; 60s gives headroom (matches the listen loop).
_TIMEOUT_SECONDS = 60.0


class PreviewServeStartupError(RuntimeError):
    """The preview grant-serve loop refused to start (no pinned key / nonce dir) — fail-closed."""


def build_grant_verifier(material: str, *, key_id: str) -> GrantVerifier:
    """Build the pinned core grant verifier from resolved Ed25519 public-key PEM (fail loud)."""
    try:
        public = serialization.load_pem_public_key(material.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise PreviewServeStartupError(
            "preview_grant_pubkey_ref is not a valid PEM public key (Ed25519 expected)"
        ) from exc
    if not isinstance(public, Ed25519PublicKey):
        raise PreviewServeStartupError(
            "preview_grant_pubkey_ref is not an Ed25519 public key (algorithm mismatch)"
        )
    return GrantVerifier(public, key_id=key_id)


class PreviewGrantServer:
    """Verify one signed grant and read the single file it names (the agent side of the pull)."""

    def __init__(
        self,
        *,
        verifier: GrantVerifier,
        nonce_store: NonceStore,
        host_id: str,
        fetcher: FileFetcher | None = None,
    ) -> None:
        self._verifier = verifier
        self._nonce_store = nonce_store
        self._host_id = host_id
        self._fetcher = fetcher or LocalFileFetcher()

    async def serve(self, signed: SignedFileGrant, *, max_bytes: int) -> bytes:
        """Verify the grant fail-closed, then read exactly the one file it names.

        Raises :class:`~fathom.preview.grant.GrantVerificationError` /
        :class:`~fathom.preview.grant.GrantReplayError` on a bad/replayed grant (no FS access), or
        :class:`~fathom.preview.types.PreviewError` if the named file cannot be read safely.
        """
        grant = await verify_grant(
            signed,
            verifier=self._verifier,
            nonce_store=self._nonce_store,
            expected_host_id=self._host_id,
        )
        # The catalogue host_id is irrelevant to a local read (LocalFileFetcher keys on path+inode);
        # the grant's (path, inode) IS the identity, re-checked O_NOFOLLOW + fstat inside the fetch.
        entry = ResolvedEntry(
            entry_id=grant.entry_id,
            host_id=0,
            volume_id=grant.volume_id,
            path=grant.path,
            inode=grant.inode,
            content_hash=grant.content_hash,
        )
        return await self._fetcher.fetch(entry, max_bytes=max_bytes)


async def _serve_error(client: httpx.AsyncClient, grant_id: str, reason: str) -> None:
    """Best-effort: tell core the grant could not be served so its pull fails fast (not on TTL)."""
    try:
        await client.post(
            SERVE_PATH, json=ServeRequest(grant_id=grant_id, error=reason).model_dump(mode="json")
        )
    except httpx.HTTPError:  # core's pull times out anyway; never crash the daemon on this
        pass


async def handle_one(client: httpx.AsyncClient, server: PreviewGrantServer) -> bool:
    """One poll → verify → read → serve cycle. ``False`` on a 204 idle tick, else ``True``.

    A grant that fails verification/read is served back as an error (no bytes) and never crashes the
    daemon (fail-closed) — core's pull then fails fast rather than waiting out the TTL.
    """
    resp = await client.post(POLL_PATH)
    if resp.status_code == 204:
        return False
    resp.raise_for_status()
    claimed = ClaimedGrant.model_validate(resp.json())
    grant_id = claimed.signed_grant.grant.grant_id
    try:
        data = await server.serve(claimed.signed_grant, max_bytes=claimed.max_bytes)
    except (GrantVerificationError, GrantReplayError, PreviewError) as exc:
        _log.warning(
            "dropping a preview grant that failed verification/read (no bytes served)",
            extra={"grant_id": grant_id, "error": str(exc)},
        )
        await _serve_error(client, grant_id, "grant could not be served")
        return True
    body = ServeRequest(grant_id=grant_id, data_b64=base64.b64encode(data).decode("ascii"))
    posted = await client.post(SERVE_PATH, json=body.model_dump(mode="json"))
    if posted.status_code != 200:
        _log.warning(
            "preview serve not accepted",
            extra={"grant_id": grant_id, "status": posted.status_code},
        )
    return True


def build_server_from_config(
    config: AgentConfig, *, secret_provider: SecretProvider
) -> PreviewGrantServer:
    """Assemble the fail-closed :class:`PreviewGrantServer` from the agent config (ADR-014).

    Raises:
        PreviewServeStartupError: ``preview_grant_pubkey_ref`` is unset/unresolvable, or no nonce
            dir (``preview_nonce_dir`` / ``quarantine_dir``) is available for the replay ledger.
    """
    if not config.preview_grant_pubkey_ref:
        raise PreviewServeStartupError("preview grant-serve requires preview_grant_pubkey_ref")
    nonce_dir = config.preview_nonce_dir or config.quarantine_dir
    if not nonce_dir:
        raise PreviewServeStartupError(
            "preview grant-serve needs preview_nonce_dir or quarantine_dir (the nonce ledger)"
        )
    material = secret_provider(config.preview_grant_pubkey_ref)
    if not material:
        raise PreviewServeStartupError(
            "preview_grant_pubkey_ref did not resolve from the secret backend"
        )
    verifier = build_grant_verifier(material, key_id=config.preview_grant_key_id)
    nonce_db = str(Path(nonce_dir) / ".preview-nonce-ledger.sqlite")
    return PreviewGrantServer(
        verifier=verifier,
        nonce_store=SqliteNonceStore(nonce_db),
        host_id=config.host_id,
    )


async def run_preview_serve(
    config: AgentConfig,
    *,
    secret_provider: SecretProvider,
    client: httpx.AsyncClient | None = None,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run the preview grant-serve loop until ``stop_event`` is set. Fail-closed at startup.

    Builds the server (raising :class:`PreviewServeStartupError` on a missing precondition *before*
    any connection), then long-polls core over the CA-pinned mTLS client, verifying + reading +
    serving one file per grant. ``client`` is injectable for tests.
    """
    server = build_server_from_config(config, secret_provider=secret_provider)
    owns_client = client is None
    active = client or mtls_client(config, timeout=_TIMEOUT_SECONDS)
    _log.info(
        "agent preview grant-serve started",
        extra={"host_id": config.host_id, "key_id": config.preview_grant_key_id},
    )
    try:
        while stop_event is None or not stop_event.is_set():
            try:
                await handle_one(active, server)
            except (
                httpx.TransportError,
                httpx.HTTPStatusError,
                ValueError,
                ValidationError,
            ) as exc:
                # Transport blip OR a malformed/non-JSON 200 (e.g. a reverse-proxy interstitial):
                # log + back off, never crash the daemon. The loop must survive a core bounce or a
                # misbehaving proxy (fail-closed daemon, not a crash-loop).
                _log.warning("preview poll failed; backing off", extra={"error": str(exc)})
                await asyncio.sleep(2.0)
    finally:
        if owns_client:
            await active.aclose()
