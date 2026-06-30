"""Principal, Role, Capability and the static permission matrix (ADD 13 §§2-3).

The matrix is transcribed directly from ADD 13 §3. Role inheritance is modelled explicitly
(``viewer < operator < remediator``); ``admin`` holds all capabilities; ``auditor`` is a
**parallel** read-only role (audit + config + metadata), never below admin (ADD 13 §2).

:func:`role_has` is the single capability-lookup oracle — the FastAPI ``require`` dependency
and the auto-generated RBAC matrix test both consume it, so allow/deny stays one source of
truth (ADD 13 §9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Literal


class Role(StrEnum):
    """Fathom roles (ADD 13 §2). ``auditor`` is parallel/read-only, not below admin."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    REMEDIATOR = "remediator"
    AUDITOR = "auditor"
    ADMIN = "admin"


class Capability(StrEnum):
    """Capabilities transcribed from the ADD 13 §3 permission matrix."""

    VIEW_METADATA = "view_metadata"  # tree / charts / history
    PREVIEW = "preview"  # sandboxed file preview
    VIEW_DEDUP = "view_dedup"
    TRIGGER_METADATA_SCAN = "trigger_metadata_scan"
    TRIGGER_FULLBIT_SCAN = "trigger_fullbit_scan"
    BUILD_REMEDIATION = "build_remediation"
    EXECUTE_REMEDIATION = "execute_remediation"  # +step-up MFA
    QUARANTINE_MANAGE = "quarantine_manage"  # +step-up MFA
    READ_AUDIT = "read_audit"
    READ_CONFIG = "read_config"
    MANAGE_USERS = "manage_users"  # users / roles / scopes
    MANAGE_AGENTS = "manage_agents"  # agents / certs (PKI)
    DEPLOY_AGENT = "deploy_agent"  # deploy/enroll agents to fleet hosts (ADR-026); +step-up MFA
    MANAGE_SETTINGS = "manage_settings"  # runtime settings store (ADR-038); reveal/set-secret +MFA


# Capabilities granted to each role *in its own right* (before inheritance), straight from
# the ADD 13 §3 matrix. Inheritance (viewer<operator<remediator) is layered in below.
_VIEWER: frozenset[Capability] = frozenset(
    {Capability.VIEW_METADATA, Capability.PREVIEW, Capability.VIEW_DEDUP}
)
_OPERATOR_OWN: frozenset[Capability] = frozenset(
    {Capability.TRIGGER_METADATA_SCAN, Capability.TRIGGER_FULLBIT_SCAN}
)
_REMEDIATOR_OWN: frozenset[Capability] = frozenset(
    {
        Capability.BUILD_REMEDIATION,
        Capability.EXECUTE_REMEDIATION,
        Capability.QUARANTINE_MANAGE,
    }
)
_AUDITOR: frozenset[Capability] = frozenset(
    {
        Capability.VIEW_METADATA,
        Capability.PREVIEW,
        Capability.VIEW_DEDUP,
        Capability.READ_AUDIT,
        Capability.READ_CONFIG,
    }
)

_OPERATOR: frozenset[Capability] = _VIEWER | _OPERATOR_OWN
_REMEDIATOR: frozenset[Capability] = _OPERATOR | _REMEDIATOR_OWN
# admin = all capabilities (full control incl. users/agents/config + reads audit).
_ADMIN: frozenset[Capability] = frozenset(Capability) | _REMEDIATOR | _AUDITOR

_ROLE_CAPS: dict[Role, frozenset[Capability]] = {
    Role.VIEWER: _VIEWER,
    Role.OPERATOR: _OPERATOR,
    Role.REMEDIATOR: _REMEDIATOR,
    Role.AUDITOR: _AUDITOR,
    Role.ADMIN: _ADMIN,
}

# Capabilities that mutate destructive state and therefore require fresh step-up MFA
# (ADD 13 §4, ADD 03 §6). The destructive write path is a separate component; this set is
# the contract it consumes.
STEP_UP_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.EXECUTE_REMEDIATION,
        Capability.QUARANTINE_MANAGE,
        Capability.DEPLOY_AGENT,
    }
)


def role_has(role: Role, cap: Capability) -> bool:
    """Return whether ``role`` grants ``cap`` (static ADD 13 §3 matrix incl. inheritance)."""
    return cap in _ROLE_CAPS[role]


def role_capabilities(role: Role) -> frozenset[Capability]:
    """Return the full (inheritance-resolved) capability set for ``role``."""
    return _ROLE_CAPS[role]


PrincipalSource = Literal["local", "forward", "oidc"]


def coerce_source(value: str) -> PrincipalSource:
    """Narrow a stored source string to a :data:`PrincipalSource` (defaults to ``local``)."""
    if value == "forward":
        return "forward"
    if value == "oidc":
        return "oidc"
    return "local"


@dataclass(frozen=True, slots=True)
class Grant:
    """A resolved ``(role, scope)`` assignment for a principal (server-authoritative)."""

    role: Role
    scope_kind: Literal["global", "host", "volume"]
    host_id: int | None = None
    volume_id: int | None = None


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated human identity with its effective grants (ADD 13 §1).

    ``mfa_authenticated_at`` is the server-stored step-up timestamp from the session — never
    client-supplied — which :func:`fathom.auth.mfa.is_step_up_fresh` checks against the
    freshness window.
    """

    subject: str
    source: PrincipalSource
    user_id: int
    display_name: str | None = None
    groups: tuple[str, ...] = ()
    grants: tuple[Grant, ...] = ()
    mfa_authenticated_at: datetime | None = None
    session_id: int | None = None

    def has_capability(self, cap: Capability) -> bool:
        """Return whether *any* held grant's role confers ``cap`` (pre-scope; ADD 13 §4)."""
        return any(role_has(g.role, cap) for g in self.grants)


@dataclass(slots=True)
class AuthContext:
    """Mutable per-request auth context (reserved for future request-scoped caching)."""

    principal: Principal
    extras: dict[str, object] = field(default_factory=dict)
