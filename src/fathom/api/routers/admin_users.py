"""Admin user / role / assignment management (ADD 13 §§1-3, §8).

Every route is gated by the ``MANAGE_USERS`` capability (admin only, ADD 13 §3) and every
mutation is audited — who granted what to whom (audit-before-act, ADD 13 §8). Scope is
server-authoritative: assignments are written here and are the *only* source the read/write
enforcement later trusts (never client input).

The auditor role is read-only and cannot reach these routes; deny-by-default in
:func:`fathom.api.auth_deps.require` enforces that without a special case.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.api.auth_deps import PrincipalDep, require
from fathom.api.deps import SessionDep
from fathom.auth.models import RoleAssignment, User
from fathom.auth.passwords import hash_password
from fathom.auth.principal import Capability, Role
from fathom.auth.scope import ScopeFilter
from fathom.core.audit_store import build_persistent_chain

router = APIRouter(prefix="/api/v1/users", tags=["admin"])

# Gate the whole router on MANAGE_USERS (admin). The ScopeFilter is unused for user admin
# (global by definition) but resolving it keeps deny-by-default uniform.
ManageUsersDep = Annotated[ScopeFilter, Depends(require(Capability.MANAGE_USERS))]

_VALID_ROLES = frozenset(r.value for r in Role)
_VALID_SCOPE_KINDS = frozenset({"global", "host", "volume"})
_ADMIN = Role.ADMIN.value


async def _audit(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str,
    before: dict[str, object],
    result: str,
) -> None:
    """Append a user-admin event to the durable, hash-chained audit log (one estate-wide chain).

    Wired to the persistent sink (was a no-op): each append stages an audit row on ``session`` so it
    commits with the request. Auditing the *whole* mutation surface (grants/revokes/creates) is the
    point of ADD 13 §8 — a silent grant is exactly what the chain exists to make tamper-evident."""
    chain = await build_persistent_chain(session)
    chain.append(actor=actor, action=action, target=target, before_state=before, result=result)


class CreateUserRequest(BaseModel):
    """Create a local user (federated users are provisioned on first login instead)."""

    username: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=8, max_length=1024)


class UserOut(BaseModel):
    """A user record (never exposes the password hash)."""

    id: int
    subject: str
    source: str
    display_name: str | None
    is_active: bool


class CreateAssignmentRequest(BaseModel):
    """Grant a ``(role, scope)`` assignment to a user (ADD 13 §§2-3)."""

    role: str = Field(min_length=1, max_length=32)
    scope_kind: str = Field(min_length=1, max_length=16)
    host_id: int | None = None
    volume_id: int | None = None


class AssignmentOut(BaseModel):
    """A persisted assignment."""

    id: int
    user_id: int
    role: str
    scope_kind: str
    host_id: int | None
    volume_id: int | None


def _validate_assignment(body: CreateAssignmentRequest) -> None:
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unknown role"
        )
    if body.scope_kind not in _VALID_SCOPE_KINDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unknown scope_kind"
        )
    if body.scope_kind == "host" and body.host_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="host scope needs host_id"
        )
    if body.scope_kind == "volume" and body.volume_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="volume scope needs volume_id"
        )


@router.get("", response_model=list[UserOut])
async def list_users(_scope: ManageUsersDep, session: SessionDep) -> list[UserOut]:
    """List all users (admin)."""
    users = (await session.execute(select(User).order_by(User.id))).scalars().all()
    return [UserOut.model_validate(u, from_attributes=True) for u in users]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    _scope: ManageUsersDep,
    principal: PrincipalDep,
    session: SessionDep,
) -> UserOut:
    """Create a local user with an Argon2-hashed password (audited)."""
    existing = (
        await session.execute(
            select(User).where(User.source == "local", User.subject == body.username)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="user exists")
    user = User(
        subject=body.username,
        source="local",
        display_name=body.display_name,
        password_hash=hash_password(body.password),
        is_active=True,
    )
    session.add(user)
    await session.flush()
    await _audit(
        session,
        actor=principal.subject,
        action="users.create",
        target=body.username,
        before={},
        result="granted",
    )
    return UserOut.model_validate(user, from_attributes=True)


@router.post(
    "/{user_id}/assignments",
    response_model=AssignmentOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_assignment(
    user_id: int,
    body: CreateAssignmentRequest,
    _scope: ManageUsersDep,
    principal: PrincipalDep,
    session: SessionDep,
) -> AssignmentOut:
    """Grant a ``(role, scope)`` assignment to a user (audited; ADD 13 §8)."""
    _validate_assignment(body)
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown user")
    assignment = RoleAssignment(
        user_id=user_id,
        role=body.role,
        scope_kind=body.scope_kind,
        host_id=body.host_id,
        volume_id=body.volume_id,
        granted_by=principal.subject,
    )
    session.add(assignment)
    await session.flush()
    await _audit(
        session,
        actor=principal.subject,
        action="users.grant",
        target=f"user:{user_id}:{body.role}:{body.scope_kind}",
        before={},
        result="granted",
    )
    return AssignmentOut.model_validate(assignment, from_attributes=True)


@router.get("/{user_id}/assignments", response_model=list[AssignmentOut])
async def list_assignments(
    user_id: int,
    _scope: ManageUsersDep,
    session: SessionDep,
) -> list[AssignmentOut]:
    """List a user's role/scope assignments (admin).

    Read counterpart to the grant/revoke routes: returns the server-authoritative
    :class:`AssignmentOut` rows the enforcement layer trusts (ADD 13 §§2-3), so an operator can
    review exactly what a principal has been granted before adding or revoking. Gated on the same
    ``MANAGE_USERS`` capability as the rest of the router; 404 for an unknown ``user_id``."""
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown user")
    assignments = (
        await session.execute(
            select(RoleAssignment)
            .where(RoleAssignment.user_id == user_id)
            .order_by(RoleAssignment.id)
        )
    ).scalars().all()
    return [AssignmentOut.model_validate(a, from_attributes=True) for a in assignments]


@router.delete("/{user_id}/assignments/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_assignment(
    user_id: int,
    assignment_id: int,
    _scope: ManageUsersDep,
    principal: PrincipalDep,
    session: SessionDep,
) -> None:
    """Revoke an assignment (audited; instant effect on the next request)."""
    assignment = await session.get(RoleAssignment, assignment_id)
    if assignment is None or assignment.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown assignment")
    # Lockout guard: never revoke the LAST global-admin grant in the estate, or no one could ever
    # manage users/settings again (ADD 13). Refuse with 409 so the operator must grant another admin
    # first. Counts other global-admin assignments (this one excluded).
    if assignment.role == _ADMIN and assignment.scope_kind == "global":
        others = (
            await session.execute(
                select(func.count())
                .select_from(RoleAssignment)
                .where(
                    RoleAssignment.role == _ADMIN,
                    RoleAssignment.scope_kind == "global",
                    RoleAssignment.id != assignment_id,
                )
            )
        ).scalar_one()
        if others == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="cannot revoke the last global admin",
            )
    before: dict[str, object] = {
        "role": assignment.role,
        "scope_kind": assignment.scope_kind,
        "host_id": assignment.host_id,
        "volume_id": assignment.volume_id,
    }
    await session.delete(assignment)
    await session.flush()
    await _audit(
        session,
        actor=principal.subject,
        action="users.revoke",
        target=f"user:{user_id}:assignment:{assignment_id}",
        before=before,
        result="granted",
    )
