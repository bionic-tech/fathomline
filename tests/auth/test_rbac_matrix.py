"""Auto-generated RBAC matrix tests (ADD 13 §3 / §9).

The expected matrix is transcribed independently from ADD 13 §3 and asserted against the
implementation's :func:`role_has`, so a divergence between the table and the code is caught.
In-scope vs out-of-scope is exercised at the :class:`ScopeFilter` level: an in-scope grant
allows the target, an out-of-scope one raises 403.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from fathom.auth.principal import Capability, Grant, Role, role_has
from fathom.auth.scope import ScopeFilter

# Expected allow set per role, transcribed from ADD 13 §3 (independent of the code's matrix).
_EXPECTED: dict[Role, set[Capability]] = {
    Role.VIEWER: {Capability.VIEW_METADATA, Capability.PREVIEW, Capability.VIEW_DEDUP},
    Role.OPERATOR: {
        Capability.VIEW_METADATA,
        Capability.PREVIEW,
        Capability.VIEW_DEDUP,
        Capability.TRIGGER_METADATA_SCAN,
        Capability.TRIGGER_FULLBIT_SCAN,
    },
    Role.REMEDIATOR: {
        Capability.VIEW_METADATA,
        Capability.PREVIEW,
        Capability.VIEW_DEDUP,
        Capability.TRIGGER_METADATA_SCAN,
        Capability.TRIGGER_FULLBIT_SCAN,
        Capability.BUILD_REMEDIATION,
        Capability.EXECUTE_REMEDIATION,
        Capability.QUARANTINE_MANAGE,
    },
    Role.AUDITOR: {
        Capability.VIEW_METADATA,
        Capability.PREVIEW,
        Capability.VIEW_DEDUP,
        Capability.READ_AUDIT,
        Capability.READ_CONFIG,
    },
    Role.ADMIN: set(Capability),  # admin = all
}


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("cap", list(Capability))
def test_role_capability_matrix(role: Role, cap: Capability) -> None:
    assert role_has(role, cap) is (cap in _EXPECTED[role])


def test_auditor_cannot_mutate() -> None:
    mutating = {
        Capability.TRIGGER_METADATA_SCAN,
        Capability.TRIGGER_FULLBIT_SCAN,
        Capability.BUILD_REMEDIATION,
        Capability.EXECUTE_REMEDIATION,
        Capability.QUARANTINE_MANAGE,
        Capability.MANAGE_USERS,
        Capability.MANAGE_AGENTS,
    }
    for cap in mutating:
        assert role_has(Role.AUDITOR, cap) is False


def test_scope_in_scope_allows() -> None:
    grants = (Grant(role=Role.VIEWER, scope_kind="host", host_id=1),)
    scope = ScopeFilter.from_grants(grants, Capability.VIEW_METADATA)
    scope.check_target(host_id=1)  # no raise


def test_scope_out_of_scope_denies() -> None:
    grants = (Grant(role=Role.VIEWER, scope_kind="host", host_id=1),)
    scope = ScopeFilter.from_grants(grants, Capability.VIEW_METADATA)
    with pytest.raises(HTTPException) as exc:
        scope.check_target(host_id=2)
    assert exc.value.status_code == 403


def test_volume_scope_targets() -> None:
    grants = (Grant(role=Role.VIEWER, scope_kind="volume", volume_id=7),)
    scope = ScopeFilter.from_grants(grants, Capability.VIEW_METADATA)
    scope.check_target(host_id=99, volume_id=7)  # volume in scope → allowed
    with pytest.raises(HTTPException):
        scope.check_target(host_id=99, volume_id=8)


def test_deny_by_default_no_grant() -> None:
    # No grant confers the capability → empty, non-global scope → deny-all (fail-closed).
    scope = ScopeFilter.from_grants((), Capability.VIEW_METADATA)
    assert scope.is_empty is True
    with pytest.raises(HTTPException):
        scope.check_target(host_id=1)


def test_multiple_grants_union_host_and_volume() -> None:
    """(viewer, host A) + (viewer, volume V) unions host_ids and volume_ids (EC-rbac-18)."""
    grants = (
        Grant(role=Role.VIEWER, scope_kind="host", host_id=3),
        Grant(role=Role.VIEWER, scope_kind="volume", volume_id=42),
    )
    scope = ScopeFilter.from_grants(grants, Capability.VIEW_METADATA)
    assert scope.is_global is False
    assert scope.host_ids == frozenset({3})
    assert scope.volume_ids == frozenset({42})
    scope.check_target(host_id=3, volume_id=999)  # reached via the host grant
    scope.check_target(host_id=999, volume_id=42)  # reached via the volume grant


def test_volume_grant_reaches_volume_regardless_of_host() -> None:
    """A volume-scoped grant reaches exactly that volume under any host id (EC-rbac-28)."""
    grants = (Grant(role=Role.VIEWER, scope_kind="volume", volume_id=7),)
    scope = ScopeFilter.from_grants(grants, Capability.VIEW_METADATA)
    for host_id in (1, 2, 999):
        scope.check_target(host_id=host_id, volume_id=7)  # host-independent: always allowed
    # No host is in scope, and a different volume is denied.
    with pytest.raises(HTTPException):
        scope.check_target(host_id=1, volume_id=8)
