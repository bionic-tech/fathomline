"""Auth provider protocol + ordered, local-first chain resolver (ADD 03 §2, ADR-009).

The chain is resolved in priority order per owner ruling: (1) built-in LOCAL users,
(2) forward-auth header trust, (3) app-native OIDC. The first provider that returns a
:class:`Principal` wins; if none authenticate the request, the chain returns ``None`` and
the caller responds 401 (deny-by-default, fail-closed). A weaker provider can never shadow a
stronger identity because ordering is fixed and the *first* success short-circuits.

Providers never invent grants: identity (subject/source/groups) is resolved here, and the
authoritative ``(role, scope)`` grants are loaded server-side from the assignment store by
the FastAPI dependency (:func:`fathom.api.auth_deps.current_principal`).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.principal import Principal


@runtime_checkable
class AuthProvider(Protocol):
    """A pluggable authentication provider (ADD 03 §2)."""

    name: str

    async def authenticate(self, request: Request, session: AsyncSession) -> Principal | None:
        """Return an authenticated principal, or ``None`` to defer to the next provider."""
        ...


async def resolve_principal(
    providers: list[AuthProvider],
    request: Request,
    session: AsyncSession,
) -> Principal | None:
    """Run providers in order; return the first authenticated principal, else ``None``."""
    for provider in providers:
        principal = await provider.authenticate(request, session)
        if principal is not None:
            return principal
    return None
