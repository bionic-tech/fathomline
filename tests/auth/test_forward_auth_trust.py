"""Forward-auth header-trust tests — the highest-risk provider (ADD 03 §2).

Headers from an untrusted source must be ignored (no identity spoofing); only a request from
the configured trusted-proxy CIDR may assert ``Remote-User`` / ``Remote-Groups``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from fathom.api.auth_deps import require
from fathom.auth.models import IdentityBinding
from fathom.auth.principal import Capability, Role
from fathom.auth.providers.forward_auth import (
    REMOTE_GROUPS_HEADER,
    REMOTE_USER_HEADER,
    ForwardAuthProvider,
    _is_trusted_source,
)
from fathom.core import db


def test_trusted_source_cidr_match() -> None:
    assert _is_trusted_source("10.0.0.5", ("10.0.0.0/8",)) is True
    assert _is_trusted_source("192.168.1.1", ("10.0.0.0/8",)) is False
    assert _is_trusted_source(None, ("10.0.0.0/8",)) is False
    # No configured trusted source → trust nobody (fail-closed).
    assert _is_trusted_source("10.0.0.5", ()) is False


def _request(*, ip: str | None, user: str | None, groups: str = "") -> MagicMock:
    req = MagicMock()
    req.client = MagicMock(host=ip) if ip is not None else None
    headers: dict[str, str] = {}
    if user is not None:
        headers[REMOTE_USER_HEADER] = user
    if groups:
        headers[REMOTE_GROUPS_HEADER] = groups
    req.headers = headers
    return req


async def test_untrusted_source_headers_ignored(api_client: object) -> None:
    provider = ForwardAuthProvider(("10.0.0.0/8",))
    req = _request(ip="203.0.113.9", user="evil-admin", groups="fathom-admins")
    async with db.session_scope() as session:
        principal = await provider.authenticate(req, session)
    assert principal is None  # spoofed identity from an untrusted source → ignored


async def test_trusted_source_maps_groups_to_role(api_client: object) -> None:
    async with db.session_scope() as session:
        session.add(IdentityBinding(group_claim="fathom-admins", role=Role.ADMIN.value))
    provider = ForwardAuthProvider(("10.0.0.0/8",))
    req = _request(ip="10.0.0.7", user="alice", groups="fathom-admins,other")
    async with db.session_scope() as session:
        principal = await provider.authenticate(req, session)
    assert principal is not None
    assert principal.subject == "alice"
    assert principal.source == "forward"
    assert any(g.role == Role.ADMIN for g in principal.grants)


async def test_missing_user_header_defers(api_client: object) -> None:
    provider = ForwardAuthProvider(("10.0.0.0/8",))
    req = _request(ip="10.0.0.7", user=None)
    async with db.session_scope() as session:
        principal = await provider.authenticate(req, session)
    assert principal is None


@pytest.mark.parametrize("ip", ["10.0.0.1", "172.16.5.5"])
def test_multiple_cidrs(ip: str) -> None:
    assert _is_trusted_source(ip, ("10.0.0.0/8", "172.16.0.0/12")) is True


async def test_trusted_source_unmapped_groups_authenticates_with_zero_grants(
    api_client: object,
) -> None:
    """Remote groups that map to no role → authenticated forward principal with grants=[],
    and every capability denied 403 (deny-by-default; EC-auth-32)."""
    provider = ForwardAuthProvider(("10.0.0.0/8",))
    req = _request(ip="10.0.0.7", user="grantless-gary", groups="unmapped-group")
    async with db.session_scope() as session:
        principal = await provider.authenticate(req, session)
    assert principal is not None  # identity established despite no grants
    assert principal.source == "forward"
    assert principal.grants == ()
    # Every capability is denied (insufficient capability) — no grant confers anything.
    for cap in Capability:
        with pytest.raises(HTTPException) as exc:
            await require(cap)(principal)
        assert exc.value.status_code == 403
