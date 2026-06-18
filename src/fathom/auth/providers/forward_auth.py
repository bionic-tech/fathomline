"""Forward-auth header trust provider (ADD 03 §2; highest-risk provider).

A reverse proxy (authelia / authentik) that has already authenticated the user passes
verified identity headers (``Remote-User`` / ``Remote-Groups``). These are trusted **only**
when the request demonstrably originates from the configured trusted proxy source — otherwise
the headers are spoofable and are ignored (fail-closed). This is the single most dangerous
provider: a misconfigured trust source would let any client assume admin, so the source check
is mandatory and is covered by ``test_forward_auth_trust``.

Group claims map to roles via the local IdentityBinding table (ADD 13 §7); the resulting
grants are GLOBAL-scoped (the proxy asserts estate-wide identity), matching the documented
default that group→role is the source of truth for federated principals.
"""

from __future__ import annotations

import ipaddress

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.principal import Grant, Principal
from fathom.auth.store import roles_for_groups, upsert_federated_user

REMOTE_USER_HEADER = "Remote-User"
REMOTE_GROUPS_HEADER = "Remote-Groups"


def _client_ip(request: Request) -> str | None:
    client = request.client
    return client.host if client is not None else None


def _is_trusted_source(ip: str | None, trusted_cidrs: tuple[str, ...]) -> bool:
    """Return whether ``ip`` falls within any configured trusted-proxy CIDR (fail-closed)."""
    if ip is None or not trusted_cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in trusted_cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


class ForwardAuthProvider:
    """Trusts proxy-verified identity headers from the configured trusted source only."""

    name = "forward"

    def __init__(self, trusted_proxy_cidrs: tuple[str, ...]) -> None:
        self._trusted = trusted_proxy_cidrs

    async def authenticate(self, request: Request, session: AsyncSession) -> Principal | None:
        user_id = request.headers.get(REMOTE_USER_HEADER)
        if not user_id:
            return None
        # Spoofing guard: ignore identity headers unless the peer is the trusted proxy.
        if not _is_trusted_source(_client_ip(request), self._trusted):
            return None
        groups_raw = request.headers.get(REMOTE_GROUPS_HEADER, "")
        groups = tuple(g.strip() for g in groups_raw.split(",") if g.strip())
        user = await upsert_federated_user(
            session, source="forward", subject=user_id, display_name=user_id
        )
        roles = await roles_for_groups(session, groups=groups)
        grants = tuple(Grant(role=r, scope_kind="global") for r in roles)
        return Principal(
            subject=user.subject,
            source="forward",
            user_id=user.id,
            display_name=user.display_name,
            groups=groups,
            grants=grants,
            # Forward-auth principals have no Fathom session row; step-up is resolved from an
            # upstream claim or a local step-up (see require_step_up_mfa).
            mfa_authenticated_at=None,
        )
