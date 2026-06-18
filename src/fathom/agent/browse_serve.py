"""Agent-side live directory browse-serve loop (ADR-034 Phase 2) — read-only.

Mirrors the preview grant-serve loop (:mod:`fathom.agent.preview_serve`) but lists a directory
instead of reading a file. The agent long-polls core for a signed
:class:`~fathom.core.browse.BrowseRequest` scoped to its host, verifies it fail-closed (signature →
expiry → host scope → single-use nonce), lists exactly the one directory it names (metadata only,
via :func:`~fathom.agent.browse_lister.list_directory`), and posts the result back.

It is **read-only**: it requires a pinned core browse public key (``browse_grant_pubkey_ref``) —
absent which the loop never starts (default-off) — and does NOT require ``write_enabled`` /
``quarantine_dir`` (the remediation gates). No file contents ever cross the channel.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from fathom.agent.browse_lister import list_directory
from fathom.agent.config import AgentConfig
from fathom.agent.transport.push import mtls_client
from fathom.core.browse import (
    BrowseReplayError,
    BrowseResult,
    BrowseVerificationError,
    BrowseVerifier,
    ClaimedBrowse,
    SignedBrowseRequest,
    verify_browse_request,
)
from fathom.core.remediation.nonce_store import SqliteNonceStore
from fathom.core.remediation.signing import NonceStore
from fathom.logging import get_logger

_log = get_logger("fathom.agent.browse_serve")

SecretProvider = Callable[[str], str]

POLL_PATH = "/api/v1/agents/browse/poll"
RESULT_PATH = "/api/v1/agents/browse/result"
# The client read timeout must exceed core's long-poll window so a parked poll is not torn down
# mid-wait; 60s gives headroom (matches the preview/listen loops).
_TIMEOUT_SECONDS = 60.0


class BrowseServeStartupError(RuntimeError):
    """The browse-serve loop refused to start (no pinned key / nonce dir) — fail-closed."""


def build_browse_verifier(material: str, *, key_id: str) -> BrowseVerifier:
    """Build the pinned core browse verifier from resolved Ed25519 public-key PEM (fail loud)."""
    try:
        public = serialization.load_pem_public_key(material.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise BrowseServeStartupError(
            "browse_grant_pubkey_ref is not a valid PEM public key (Ed25519 expected)"
        ) from exc
    if not isinstance(public, Ed25519PublicKey):
        raise BrowseServeStartupError(
            "browse_grant_pubkey_ref is not an Ed25519 public key (algorithm mismatch)"
        )
    return BrowseVerifier(public, key_id=key_id)


class BrowseServer:
    """Verify one signed browse request and list the single directory it names (read-only)."""

    def __init__(
        self,
        *,
        verifier: BrowseVerifier,
        nonce_store: NonceStore,
        host_id: str,
    ) -> None:
        self._verifier = verifier
        self._nonce_store = nonce_store
        self._host_id = host_id

    async def serve(self, signed: SignedBrowseRequest) -> BrowseResult:
        """Verify fail-closed, then list the one directory the request names (metadata only)."""
        request = await verify_browse_request(
            signed,
            verifier=self._verifier,
            nonce_store=self._nonce_store,
            expected_host_id=self._host_id,
        )
        # list_directory is sync os.scandir work — run it off the event loop.
        return await asyncio.to_thread(list_directory, request)


async def _result_error(client: httpx.AsyncClient, request_id: str, path: str, reason: str) -> None:
    """Best-effort: tell core the browse failed so its request fails fast (not on the TTL)."""
    try:
        body = BrowseResult(request_id=request_id, path=path, error=reason)
        await client.post(RESULT_PATH, json=body.model_dump(mode="json"))
    except httpx.HTTPError:  # core's request times out anyway; never crash the daemon on this
        pass


async def handle_one(client: httpx.AsyncClient, server: BrowseServer) -> bool:
    """One poll → verify → list → result cycle. ``False`` on a 204 idle tick, else ``True``.

    A request that fails verification is answered with an error result and never crashes
    the daemon (fail-closed) — core's request then fails fast rather than waiting out the TTL.
    """
    resp = await client.post(POLL_PATH)
    if resp.status_code == 204:
        return False
    resp.raise_for_status()
    claimed = ClaimedBrowse.model_validate(resp.json())
    request = claimed.signed_request.request
    try:
        result = await server.serve(claimed.signed_request)
    except (BrowseVerificationError, BrowseReplayError) as exc:
        _log.warning(
            "dropping a browse request that failed verification (no listing served)",
            extra={"request_id": request.request_id, "error": str(exc)},
        )
        await _result_error(client, request.request_id, request.path, "request could not be served")
        return True
    posted = await client.post(RESULT_PATH, json=result.model_dump(mode="json"))
    if posted.status_code != 200:
        _log.warning(
            "browse result not accepted",
            extra={"request_id": request.request_id, "status": posted.status_code},
        )
    return True


def build_server_from_config(
    config: AgentConfig, *, secret_provider: SecretProvider
) -> BrowseServer:
    """Assemble the fail-closed :class:`BrowseServer` from the agent config (ADR-034 Phase 2).

    Raises:
        BrowseServeStartupError: ``browse_grant_pubkey_ref`` is unset/unresolvable, or no nonce dir
            (``browse_nonce_dir`` / ``preview_nonce_dir`` / ``quarantine_dir``) is available.
    """
    if not config.browse_grant_pubkey_ref:
        raise BrowseServeStartupError("browse-serve requires browse_grant_pubkey_ref")
    nonce_dir = config.browse_nonce_dir or config.preview_nonce_dir or config.quarantine_dir
    if not nonce_dir:
        raise BrowseServeStartupError(
            "browse-serve needs browse_nonce_dir/preview_nonce_dir/quarantine_dir (nonce ledger)"
        )
    material = secret_provider(config.browse_grant_pubkey_ref)
    if not material:
        raise BrowseServeStartupError(
            "browse_grant_pubkey_ref did not resolve from the secret backend"
        )
    verifier = build_browse_verifier(material, key_id=config.browse_grant_key_id)
    nonce_db = str(Path(nonce_dir) / ".browse-nonce-ledger.sqlite")
    return BrowseServer(
        verifier=verifier,
        nonce_store=SqliteNonceStore(nonce_db),
        host_id=config.host_id,
    )


async def run_browse_serve(
    config: AgentConfig,
    *,
    secret_provider: SecretProvider,
    client: httpx.AsyncClient | None = None,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run the browse-serve loop until ``stop_event`` is set. Fail-closed at startup.

    Builds the server (raising the startup error on a missing precondition *before* any
    connection), then long-polls core over the CA-pinned mTLS client, verifying + listing + serving
    one directory per request. ``client`` is injectable for tests.
    """
    server = build_server_from_config(config, secret_provider=secret_provider)
    owns_client = client is None
    active = client or mtls_client(config, timeout=_TIMEOUT_SECONDS)
    _log.info(
        "agent browse-serve started",
        extra={"host_id": config.host_id, "key_id": config.browse_grant_key_id},
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
                # log + back off, never crash the daemon (fail-closed daemon, not a crash-loop).
                _log.warning("browse poll failed; backing off", extra={"error": str(exc)})
                await asyncio.sleep(2.0)
    finally:
        if owns_client:
            await active.aclose()
