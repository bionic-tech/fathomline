"""Local user provider — Argon2 passwords + server-side sessions (ADD 03 §2, ADR-009).

The first link in the chain (owner ruling: LOCAL users first). Authentication on a normal
request is by **session token** (httpOnly cookie or ``Authorization: Bearer`` for API
clients): the token is looked up server-side, and the bound user's grants are resolved from
the assignment store. The username/password *login* flow that mints a session lives in
:func:`login`; the provider itself only consumes an existing session.

Credentials are never logged (count-only); a wrong password and an unknown user both fail
the same way (no user enumeration).
"""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.models import User
from fathom.auth.passwords import hash_password, needs_rehash, verify_password
from fathom.auth.principal import Principal, coerce_source
from fathom.auth.sessions import create_session, lookup_session
from fathom.auth.store import get_active_user, grants_for_user

SESSION_COOKIE = "fathom_session"
_BEARER_PREFIX = "Bearer "


def extract_session_token(request: Request) -> str | None:
    """Return the session token from the cookie or ``Authorization: Bearer`` header."""
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        return cookie
    header = request.headers.get("Authorization")
    if header and header.startswith(_BEARER_PREFIX):
        return header[len(_BEARER_PREFIX) :].strip() or None
    return None


class LocalSessionProvider:
    """Authenticates a request from its server-side session (local source)."""

    name = "local"

    async def authenticate(self, request: Request, session: AsyncSession) -> Principal | None:
        token = extract_session_token(request)
        if token is None:
            return None
        row = await lookup_session(session, raw_token=token)
        if row is None:
            return None
        # Resolve the bound user directly by id (the session already authenticates them).
        user = await session.get(User, row.user_id)
        if user is None or not user.is_active:
            return None
        grants = await grants_for_user(session, user_id=user.id)
        return Principal(
            subject=user.subject,
            source=coerce_source(user.source),
            user_id=user.id,
            display_name=user.display_name,
            grants=grants,
            mfa_authenticated_at=row.mfa_authenticated_at,
            session_id=row.id,
        )


async def login(
    session: AsyncSession,
    *,
    username: str,
    password: str,
    ttl_seconds: int,
    ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[Principal, str] | None:
    """Verify local credentials and mint a session; return ``(principal, raw_token)`` or None.

    Returns ``None`` on any failure (unknown user, inactive, wrong password) — the caller
    maps that to a uniform 401, preventing user enumeration. Rehashes the stored hash in
    place when Argon2 cost parameters have changed.
    """
    user = await get_active_user(session, source="local", subject=username)
    if user is None or user.password_hash is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        await session.flush()
    row, raw = await create_session(
        session, user_id=user.id, ttl_seconds=ttl_seconds, ip=ip, user_agent=user_agent
    )
    grants = await grants_for_user(session, user_id=user.id)
    principal = Principal(
        subject=user.subject,
        source="local",
        user_id=user.id,
        display_name=user.display_name,
        grants=grants,
        mfa_authenticated_at=row.mfa_authenticated_at,
        session_id=row.id,
    )
    return principal, raw
