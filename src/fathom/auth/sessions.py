"""Server-side session token mint / verify (ADD 03 §2).

Sessions are server-side and revocable for instant lockout. The opaque token is minted from
a CSPRNG and returned to the client *once*; only its hash is stored at rest, so a database
read cannot recover a live session token. Lookups are by hash, with absolute-expiry and
revocation both enforced (fail-closed). Step-up MFA freshness is tracked on the row
(``mfa_authenticated_at``), keeping it server-authoritative and unforgeable.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.models import UserSession

_TOKEN_BYTES = 32  # 256-bit opaque token


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _as_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp (SQLite round-trips drop tzinfo) to UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def hash_token(token: str) -> str:
    """Return the at-rest hash of an opaque session token (SHA-256 hex)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint_token() -> str:
    """Return a fresh, URL-safe, opaque session token (returned to the client once)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


async def create_session(
    session: AsyncSession,
    *,
    user_id: int,
    ttl_seconds: int,
    ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[UserSession, str]:
    """Create a session row and return ``(row, raw_token)`` — the raw token is shown once."""
    raw = mint_token()
    row = UserSession(
        user_id=user_id,
        token_hash=hash_token(raw),
        expires_at=_now() + timedelta(seconds=ttl_seconds),
        ip=ip,
        user_agent=user_agent,
    )
    session.add(row)
    await session.flush()
    return row, raw


async def lookup_session(session: AsyncSession, *, raw_token: str) -> UserSession | None:
    """Return the live session for ``raw_token``, or ``None`` if absent/expired/revoked."""
    token_hash = hash_token(raw_token)
    row = (
        await session.execute(select(UserSession).where(UserSession.token_hash == token_hash))
    ).scalar_one_or_none()
    if row is None:
        return None
    if row.revoked_at is not None:
        return None
    if _as_utc(row.expires_at) <= _now():
        return None
    return row


async def revoke_session(session: AsyncSession, *, row: UserSession) -> None:
    """Revoke a session immediately (instant lockout)."""
    row.revoked_at = _now()
    await session.flush()


async def mark_step_up(session: AsyncSession, *, row: UserSession) -> None:
    """Stamp a fresh step-up MFA time on the session (server-authoritative; ADD 13 §4)."""
    row.mfa_authenticated_at = _now()
    await session.flush()
