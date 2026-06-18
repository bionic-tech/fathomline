"""Server-authoritative grant resolution (ADD 13 §4).

Grants are loaded **only** from the assignment store, never derived from client input. This
module is the single place that turns persisted rows into :class:`Grant` tuples and maps
group claims to roles via the local :class:`IdentityBinding` table (ADD 13 §7), used by both
the provider chain and the FastAPI dependency.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.models import IdentityBinding, RoleAssignment, User
from fathom.auth.principal import Grant, Role


def _coerce_role(value: str) -> Role | None:
    try:
        return Role(value)
    except ValueError:
        return None


def _coerce_scope_kind(value: str) -> str | None:
    return value if value in {"global", "host", "volume"} else None


async def grants_for_user(session: AsyncSession, *, user_id: int) -> tuple[Grant, ...]:
    """Return the union of ``(role, scope)`` grants persisted for ``user_id`` (ADD 13 §4)."""
    rows = (
        (await session.execute(select(RoleAssignment).where(RoleAssignment.user_id == user_id)))
        .scalars()
        .all()
    )
    grants: list[Grant] = []
    seen: set[tuple[object, object, object, object]] = set()
    for row in rows:
        role = _coerce_role(row.role)
        scope_kind = _coerce_scope_kind(row.scope_kind)
        if role is None or scope_kind is None:
            # Unknown/malformed assignment → ignore (deny-by-default; never widen access).
            continue
        # Collapse exact-duplicate assignments (same role + scope) — two identical rows grant the
        # same access, so they are one effective grant, not two (avoids a doubled "admin global" in
        # /me and the Settings page). Distinct host/volume scopes are kept separate.
        key = (role, scope_kind, row.host_id, row.volume_id)
        if key in seen:
            continue
        seen.add(key)
        grants.append(
            Grant(
                role=role,
                scope_kind=scope_kind,  # type: ignore[arg-type]
                host_id=row.host_id,
                volume_id=row.volume_id,
            )
        )
    return tuple(grants)


async def roles_for_groups(session: AsyncSession, *, groups: tuple[str, ...]) -> tuple[Role, ...]:
    """Map group claims to roles via the local IdentityBinding table (ADD 13 §7)."""
    if not groups:
        return ()
    rows = (
        (
            await session.execute(
                select(IdentityBinding).where(IdentityBinding.group_claim.in_(groups))
            )
        )
        .scalars()
        .all()
    )
    roles: list[Role] = []
    for row in rows:
        role = _coerce_role(row.role)
        if role is not None:
            roles.append(role)
    return tuple(roles)


async def get_active_user(session: AsyncSession, *, source: str, subject: str) -> User | None:
    """Return the active user for ``(source, subject)``, or ``None`` (fail-closed)."""
    user = (
        await session.execute(select(User).where(User.source == source, User.subject == subject))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        return None
    return user


async def upsert_federated_user(
    session: AsyncSession, *, source: str, subject: str, display_name: str | None
) -> User:
    """Get-or-create a forward/OIDC user record (no password; identity from the IdP)."""
    user = (
        await session.execute(select(User).where(User.source == source, User.subject == subject))
    ).scalar_one_or_none()
    if user is None:
        user = User(source=source, subject=subject, display_name=display_name, is_active=True)
        session.add(user)
        await session.flush()
    return user
