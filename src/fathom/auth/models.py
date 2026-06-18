"""SQLAlchemy 2.0 typed models for human auth + RBAC (ADD 13 §§1-3, ADD 03 §2).

These reuse the catalogue ``Base`` so a single metadata / single Alembic chain governs both
catalogue and auth schemas (one head off ``3a48eed79c3c``). Types are kept portable
(String / Integer / DateTime(timezone=True) / Boolean) so the SQLite test suite stays green
alongside PostgreSQL in production.

Security notes:
- ``User.password_hash`` is Argon2 and nullable (local users only; forward/OIDC have none).
- ``UserSession.token_hash`` stores only a hash of the opaque session token — the raw token
  never lives at rest (sessions are revocable for instant lockout).
- ``MfaEnrollment.secret_ref`` is a *reference* into the secret backend, never a raw TOTP
  secret in the database (ADR-010, no secrets in code/DB).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fathom.core.catalogue.models import Base


class User(Base):
    """A human principal — local, forward-auth, or OIDC-sourced (ADD 13 §1)."""

    __tablename__ = "auth_user"
    __table_args__ = (UniqueConstraint("source", "subject", name="uq_auth_user_source_subject"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # Local username, OIDC ``sub``, or forward-auth user id; unique within a source.
    subject: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(16))  # local | forward | oidc
    display_name: Mapped[str | None] = mapped_column(String(255), default=None)
    # Argon2 hash; NULL for forward/OIDC principals (no local password).
    password_hash: Mapped[str | None] = mapped_column(String(255), default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    assignments: Mapped[list[RoleAssignment]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class RoleAssignment(Base):
    """A ``(role, scope)`` grant to a principal (ADD 13 §§1-3).

    A principal may hold several assignments; effective grants are their union (ADD 13 §10
    Q2). Scope is one of global / host / volume; ``host_id`` / ``volume_id`` are populated
    according to ``scope_kind``.
    """

    __tablename__ = "auth_role_assignment"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id"), index=True)
    role: Mapped[str] = mapped_column(String(32))  # viewer|operator|remediator|auditor|admin
    scope_kind: Mapped[str] = mapped_column(String(16))  # global|host|volume
    host_id: Mapped[int | None] = mapped_column(ForeignKey("host.id"), default=None)
    volume_id: Mapped[int | None] = mapped_column(ForeignKey("volume.id"), default=None)
    granted_by: Mapped[str | None] = mapped_column(String(255), default=None)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped[User] = relationship(back_populates="assignments")


class UserSession(Base):
    """A server-side session — opaque token hashed at rest, revocable, short-TTL (ADD 03 §2)."""

    __tablename__ = "auth_session"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Drives step-up freshness for write routes (ADD 13 §4); NULL until MFA verified.
    mfa_authenticated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    # Optional, count-only sensitive logging (ADD 13 §8); not used for authz.
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(255), default=None)


class MfaEnrollment(Base):
    """A TOTP second-factor enrollment; the secret lives in the secret store (ADR-010)."""

    __tablename__ = "auth_mfa_enrollment"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id"), index=True)
    type: Mapped[str] = mapped_column(String(16), default="totp")
    # A reference into the secret backend — NOT the raw TOTP secret (ADR-010).
    secret_ref: Mapped[str] = mapped_column(String(255))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class IdentityBinding(Base):
    """Maps an OIDC / forward-auth group claim to a Fathom role (ADD 13 §7).

    The local source-of-truth for group→role mapping (overridable per ADD 13 §10 Q3); works
    for both OIDC group claims and forward-auth ``Remote-Groups`` headers.
    """

    __tablename__ = "auth_identity_binding"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_claim: Mapped[str] = mapped_column(String(255), unique=True)
    role: Mapped[str] = mapped_column(String(32))
