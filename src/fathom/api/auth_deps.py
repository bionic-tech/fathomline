"""FastAPI human-auth dependencies (ADD 13 §4, ADD 03 §2-3).

The deny-by-default enforcement layer. ``current_principal`` runs the ordered provider chain
(local → forward → OIDC) and 401s if no provider authenticates. ``require(capability)`` is
the per-route guard: it checks the route's required capability against the principal's grants
(deny-by-default → 403) and returns the server-authoritative :class:`ScopeFilter` the route
applies to its query / write target. ``require_step_up_mfa`` enforces 5-minute MFA freshness
on destructive write routes.

This layer is **never** attached to the agent mTLS ingest route — that boundary stays
``FingerprintDep`` in :mod:`fathom.api.deps` (ADD 03 §3, AR-0012).
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status

from fathom.api.deps import SessionDep, SettingsDep
from fathom.auth.mfa import is_step_up_fresh
from fathom.auth.principal import STEP_UP_CAPABILITIES, Capability, Principal
from fathom.auth.providers import AuthProvider, resolve_principal
from fathom.auth.providers.forward_auth import ForwardAuthProvider
from fathom.auth.providers.local import LocalSessionProvider
from fathom.auth.scope import ScopeFilter
from fathom.core.settings import Settings


def build_provider_chain(settings: Settings) -> list[AuthProvider]:
    """Build the ordered provider chain from settings (local-first; ADR-009).

    OIDC normal-request authentication is session-based (the callback mints a local session),
    so the steady-state chain is local-session + forward-auth; OIDC's interactive flow lives
    in the auth router. Forward-auth is only included when a trusted-proxy source is set
    (fail-closed: no trusted source → header trust disabled).
    """
    available: dict[str, AuthProvider] = {"local": LocalSessionProvider()}
    if settings.trusted_forward_proxy_cidrs:
        available["forward"] = ForwardAuthProvider(settings.trusted_forward_proxy_cidrs)
    chain: list[AuthProvider] = []
    for name in settings.auth_providers:
        provider = available.get(name)
        if provider is not None:
            chain.append(provider)
    # Guarantee the local provider is always present even if mis-configured out (fail-safe).
    if not any(p.name == "local" for p in chain):
        chain.insert(0, available["local"])
    return chain


async def current_principal(
    request: Request, session: SessionDep, settings: SettingsDep
) -> Principal:
    """Resolve the request's principal via the provider chain, or 401 (deny-by-default)."""
    chain = build_provider_chain(settings)
    principal = await resolve_principal(chain, request, session)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


PrincipalDep = Annotated[Principal, Depends(current_principal)]


def require(capability: Capability) -> Callable[..., Coroutine[Any, Any, ScopeFilter]]:
    """Return a dependency enforcing ``capability`` and yielding its ScopeFilter (ADD 13 §4).

    Deny-by-default: a principal without any grant whose role confers ``capability`` gets a
    403. On success the returned :class:`ScopeFilter` is server-authoritative — built only
    from the assignment store — and the route applies it to its query / write target.
    """

    async def dependency(principal: PrincipalDep) -> ScopeFilter:
        if not principal.has_capability(capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient capability",
            )
        scope = ScopeFilter.from_grants(principal.grants, capability)
        if scope.is_empty:
            # Capability held but no in-scope target → nothing authorised (fail-closed).
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="no scope for capability",
            )
        return scope

    return dependency


async def require_step_up_mfa(principal: PrincipalDep, settings: SettingsDep) -> None:
    """Enforce fresh step-up MFA on destructive write routes (ADD 13 §4; default 300s).

    A local session must carry a fresh ``mfa_authenticated_at``. For forward-auth / OIDC
    principals an upstream step-up signal may satisfy this in a later wave; absent that, a
    local step-up is required (fail-closed → 401).
    """
    if not is_step_up_fresh(
        principal.mfa_authenticated_at,
        freshness_seconds=settings.mfa_freshness_seconds,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="step-up MFA required",
        )


# Convenience guards for the capabilities that gate destructive writes (ADD 13 §4).
STEP_UP_GATED: frozenset[Capability] = STEP_UP_CAPABILITIES
