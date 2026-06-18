"""Initial local-admin bootstrap (ADR-010 — no hardcoded credentials).

The one-time admin credential is read from the environment / a Docker secret at runtime; it
is never committed to code or config. The operation is idempotent: re-running with an
already-present admin is a no-op (it does not rotate the password), so a deploy can safely
invoke it on every boot.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.models import RoleAssignment, User
from fathom.auth.passwords import hash_password
from fathom.auth.principal import Role

ADMIN_USERNAME_ENV = "FATHOM_BOOTSTRAP_ADMIN_USER"
ADMIN_PASSWORD_ENV = "FATHOM_BOOTSTRAP_ADMIN_PASSWORD"  # noqa: S105 — env var name, not a secret


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    """Outcome of a bootstrap attempt."""

    created: bool
    username: str


async def bootstrap_admin(
    session: AsyncSession, *, username: str, password: str
) -> BootstrapResult:
    """Idempotently ensure a global-admin local user exists (ADR-010).

    Creates the user with an Argon2-hashed password and a global ``admin`` assignment when
    absent; returns ``created=False`` without touching anything if the user already exists.
    """
    existing = (
        await session.execute(select(User).where(User.source == "local", User.subject == username))
    ).scalar_one_or_none()
    if existing is not None:
        return BootstrapResult(created=False, username=username)
    user = User(
        subject=username,
        source="local",
        display_name=username,
        password_hash=hash_password(password),
        is_active=True,
    )
    session.add(user)
    await session.flush()
    session.add(
        RoleAssignment(
            user_id=user.id,
            role=Role.ADMIN.value,
            scope_kind="global",
            granted_by="bootstrap",
        )
    )
    await session.flush()
    return BootstrapResult(created=True, username=username)


def read_bootstrap_credential() -> tuple[str, str]:
    """Read the one-time admin credential from the environment (never hardcoded; ADR-010)."""
    username = os.environ.get(ADMIN_USERNAME_ENV)
    password = os.environ.get(ADMIN_PASSWORD_ENV)
    if not username or not password:
        raise SystemExit(
            f"both {ADMIN_USERNAME_ENV} and {ADMIN_PASSWORD_ENV} must be set "
            "(inject via env / Docker secret — never hardcode; ADR-010)"
        )
    return username, password
