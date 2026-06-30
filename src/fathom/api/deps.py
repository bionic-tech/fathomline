"""FastAPI dependencies — DB sessions and agent identity (mTLS).

The agent's authoritative identity is its mTLS client-certificate fingerprint, not anything
in the request body. mTLS is terminated upstream (nginx/Traefik — the only intended route to
core, AR-0020), which verifies the client cert against the Fathom CA, OVERWRITES the
``X-Client-Cert-Fingerprint`` header with the verified value, and sets a shared
``X-Fathom-Proxy-Secret`` the core checks. That secret proves the request transited the mTLS
boundary: without it the core would trust a fingerprint header on a *direct* call that bypassed
the proxy (the ingest route is reachable on the internal network / localhost), letting anyone
reachable on the port forge an agent identity and poison the catalogue (AR-0010, STRIDE
Spoofing). The human-auth path is entirely separate from this dependency (read != write
boundary, AR-0012) and must never be attached to the agent ingest route.
"""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.db import get_sessionmaker
from fathom.core.settings import Settings, get_settings

CLIENT_FINGERPRINT_HEADER = "X-Client-Cert-Fingerprint"
PROXY_SECRET_HEADER = "X-Fathom-Proxy-Secret"  # noqa: S105 — a header name, not a secret value


async def db_session() -> AsyncIterator[AsyncSession]:
    """Yield a transactional session for the request (commit on success, rollback on error)."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def request_settings(request: Request) -> Settings:
    """Return the effective settings for this request (env base + in-app overrides; ADR-038).

    Reading settings from app state keeps request-time configuration (auth providers, MFA
    freshness, cookie flags, the ingest proxy secret) consistent with the settings the app was
    built with, including per-test overrides. When a runtime settings store is installed on
    ``app.state`` it overlays the operator's persisted, live-reloaded overrides on that base
    (in-app value wins) — so a setting changed in the UI takes effect on the next request, no
    restart. With no store (or no overrides) this is exactly the app-bound base.
    """
    state_settings = getattr(request.app.state, "settings", None)
    base = state_settings if isinstance(state_settings, Settings) else get_settings()
    store = getattr(request.app.state, "settings_store", None)
    if store is not None:
        return store.effective(base)  # type: ignore[no-any-return]
    return base


SettingsDep = Annotated[Settings, Depends(request_settings)]


def request_secret_provider(request: Request) -> Callable[[str], str]:
    """Return the secret resolver for this request: the in-app store in front of env/Docker.

    Composes the runtime settings store (ADR-038) ahead of the env/Docker provider (ADR-010), so a
    credential typed into the Settings UI resolves by reference exactly like an env secret. With no
    store installed this is just the env/Docker provider (unchanged behaviour).
    """
    from fathom.backends.remote import env_or_docker_secret_provider
    from fathom.core.settings_store import build_secret_provider

    store = getattr(request.app.state, "settings_store", None)
    return build_secret_provider(store, env_or_docker_secret_provider)


SecretProviderDep = Annotated[Callable[[str], str], Depends(request_secret_provider)]


def require_client_fingerprint(
    settings: SettingsDep,
    fingerprint: Annotated[str | None, Header(alias=CLIENT_FINGERPRINT_HEADER)] = None,
    proxy_secret: Annotated[str | None, Header(alias=PROXY_SECRET_HEADER)] = None,
) -> str:
    """Return the verified mTLS client-cert fingerprint, fail-closed.

    When an ingest proxy secret is configured (production), the request MUST carry the matching
    ``X-Fathom-Proxy-Secret`` that the mTLS proxy sets — otherwise the request did not transit
    that boundary and its fingerprint header is untrusted (forgeable on a direct call). The
    comparison is constant-time. When no secret is configured (dev/test), the proxy check is
    skipped and the fingerprint header is trusted directly.
    """
    expected = settings.ingest_proxy_secret
    if expected and (not proxy_secret or not hmac.compare_digest(proxy_secret, expected)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ingest must transit the trusted proxy",
        )
    if not fingerprint:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client certificate required",
        )
    return fingerprint


SessionDep = Annotated[AsyncSession, Depends(db_session)]
FingerprintDep = Annotated[str, Depends(require_client_fingerprint)]
