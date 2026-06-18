"""Admin bootstrap (ADR-010) + step-up MFA dependency tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from fathom.admin.bootstrap import bootstrap_admin
from fathom.api.auth_deps import require_step_up_mfa
from fathom.auth.principal import Principal, Role
from fathom.auth.store import grants_for_user
from fathom.core import db
from fathom.core.settings import Settings


async def test_bootstrap_creates_global_admin(api_client: object) -> None:
    async with db.session_scope() as session:
        result = await bootstrap_admin(session, username="root", password="a-long-secret-pw")
    assert result.created is True
    # Idempotent: a second run is a no-op.
    async with db.session_scope() as session:
        again = await bootstrap_admin(session, username="root", password="different-pw")
    assert again.created is False


async def test_bootstrap_admin_has_admin_grant(api_client: object) -> None:
    async with db.session_scope() as session:
        await bootstrap_admin(session, username="root2", password="a-long-secret-pw")
    from sqlalchemy import select

    from fathom.auth.models import User

    async with db.session_scope() as session:
        user = (await session.execute(select(User).where(User.subject == "root2"))).scalar_one()
        grants = await grants_for_user(session, user_id=user.id)
    assert any(g.role == Role.ADMIN and g.scope_kind == "global" for g in grants)


async def test_bootstrap_stores_argon2_hash_not_plaintext(api_client: object) -> None:
    # ADR-010: the password is Argon2-hashed at rest, never stored in the clear, and verifies.
    from sqlalchemy import select

    from fathom.auth.models import User
    from fathom.auth.passwords import verify_password

    pw = "a-long-secret-pw"
    async with db.session_scope() as session:
        await bootstrap_admin(session, username="root3", password=pw)
    async with db.session_scope() as session:
        user = (await session.execute(select(User).where(User.subject == "root3"))).scalar_one()
    assert user.password_hash != pw
    assert user.password_hash.startswith("$argon2")
    assert verify_password(pw, user.password_hash) is True
    assert verify_password("wrong", user.password_hash) is False


async def test_bootstrap_is_idempotent_and_does_not_rotate_password(api_client: object) -> None:
    # The docstring promises a re-run never rotates the password (safe to call every boot).
    from sqlalchemy import select

    from fathom.auth.models import User
    from fathom.auth.passwords import verify_password

    async with db.session_scope() as session:
        await bootstrap_admin(session, username="root4", password="original-pw")
    async with db.session_scope() as session:
        again = await bootstrap_admin(session, username="root4", password="attacker-new-pw")
    assert again.created is False
    async with db.session_scope() as session:
        user = (await session.execute(select(User).where(User.subject == "root4"))).scalar_one()
    assert verify_password("original-pw", user.password_hash) is True
    assert verify_password("attacker-new-pw", user.password_hash) is False


def test_read_bootstrap_credential_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from fathom.admin.bootstrap import (
        ADMIN_PASSWORD_ENV,
        ADMIN_USERNAME_ENV,
        read_bootstrap_credential,
    )

    monkeypatch.setenv(ADMIN_USERNAME_ENV, "admin")
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, "from-the-environment")
    assert read_bootstrap_credential() == ("admin", "from-the-environment")


@pytest.mark.parametrize("present", ["user_only", "password_only", "neither"])
def test_read_bootstrap_credential_fails_closed_when_missing(
    monkeypatch: pytest.MonkeyPatch, present: str
) -> None:
    # No hardcoded fallback (ADR-010): a missing half must abort loudly, never default.
    from fathom.admin.bootstrap import (
        ADMIN_PASSWORD_ENV,
        ADMIN_USERNAME_ENV,
        read_bootstrap_credential,
    )

    monkeypatch.delenv(ADMIN_USERNAME_ENV, raising=False)
    monkeypatch.delenv(ADMIN_PASSWORD_ENV, raising=False)
    if present == "user_only":
        monkeypatch.setenv(ADMIN_USERNAME_ENV, "admin")
    elif present == "password_only":
        monkeypatch.setenv(ADMIN_PASSWORD_ENV, "pw")
    with pytest.raises(SystemExit):
        read_bootstrap_credential()


def _principal(mfa_at: datetime | None) -> Principal:
    return Principal(subject="x", source="local", user_id=1, mfa_authenticated_at=mfa_at)


_SETTINGS = Settings()


async def test_step_up_dep_rejects_stale() -> None:
    stale = datetime.now(tz=UTC) - timedelta(seconds=10_000)
    with pytest.raises(HTTPException) as exc:
        await require_step_up_mfa(_principal(stale), _SETTINGS)
    assert exc.value.status_code == 401


async def test_step_up_dep_rejects_missing() -> None:
    with pytest.raises(HTTPException) as exc:
        await require_step_up_mfa(_principal(None), _SETTINGS)
    assert exc.value.status_code == 401


async def test_step_up_dep_allows_fresh() -> None:
    fresh = datetime.now(tz=UTC)
    await require_step_up_mfa(_principal(fresh), _SETTINGS)  # no raise
