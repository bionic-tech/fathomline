"""Agents router — read-only fleet topology (ADD 04, frontend ADD §4).

The Agents tab's data source: the registered hosts and their agent liveness (OS, agent
version, last mTLS contact, catalogued-volume count). It is a *read* surface — gated by
``VIEW_METADATA`` and scope-filtered so a non-global principal sees only hosts it can reach
(a host it has a host-scoped grant on, or a host carrying a volume it has a volume-scoped grant
on). Managing agents/certs (PKI) is a separate, admin-only ``MANAGE_AGENTS`` surface; this
route never mutates anything (security_constraints: read != write).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import exists, false, func, or_, select
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import ColumnElement

from fathom.api.auth_deps import PrincipalDep, require
from fathom.api.deps import FingerprintDep, SessionDep
from fathom.api.schemas import AgentConfigOverrideIn, HostOut
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core.agent_runs import latest_run_by_host
from fathom.core.audit_store import build_persistent_chain
from fathom.core.catalogue.models import Host, Volume

router = APIRouter(prefix="/api/v1", tags=["agents"])

ViewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]
ManageScopeDep = Annotated[ScopeFilter, Depends(require(Capability.MANAGE_AGENTS))]


def _host_scope_predicate(scope: ScopeFilter) -> ColumnElement[bool]:
    """A WHERE predicate: a host is visible iff in scope (fail-closed for an empty scope).

    Built only from the server-authoritative :class:`ScopeFilter`: a host is visible when its id
    is host-scoped, OR it carries a volume the principal has a volume-scoped grant on. An empty
    non-global scope yields ``false()`` so nothing leaks. ``apply()`` is not used here because a
    purely volume-scoped principal must still see the *host* that owns its in-scope volumes — a
    relationship a single-column host filter cannot express.
    """
    predicates: list[ColumnElement[bool]] = []
    if scope.host_ids:
        predicates.append(Host.id.in_(scope.host_ids))
    if scope.volume_ids:
        # A distinct Volume alias for the EXISTS subquery: the outer query already joins ``Volume``
        # (for the count), so reusing it here would auto-correlate the subquery's only FROM away.
        scoped_vol = aliased(Volume)
        predicates.append(
            exists(
                select(scoped_vol.id).where(
                    scoped_vol.host_id == Host.id, scoped_vol.id.in_(scope.volume_ids)
                )
            )
        )
    return or_(*predicates) if predicates else false()


@router.get("/agents", response_model=list[HostOut])
async def list_agents(session: SessionDep, scope: ViewScopeDep) -> list[HostOut]:
    """List registered hosts + agent liveness and volume count (scope-filtered, read-only)."""
    volume_count = func.count(Volume.id)
    stmt = (
        select(Host, volume_count)
        .outerjoin(Volume, Volume.host_id == Host.id)
        .group_by(Host.id)
        .order_by(Host.id)
    )
    if not scope.is_global:
        stmt = stmt.where(_host_scope_predicate(scope))
    rows = (await session.execute(stmt)).all()
    # Per-host last-run outcome (observability): "did the last scan succeed?", not just liveness.
    latest = await latest_run_by_host(session, [host.id for host, _ in rows])
    out: list[HostOut] = []
    for host, count in rows:
        run = latest.get(host.id)
        out.append(
            HostOut(
                id=host.id,
                name=host.name,
                os=host.os,
                agent_version=host.agent_version,
                last_seen=host.last_seen,
                volume_count=count,
                last_run_outcome=run.outcome if run else None,
                last_run_finished_at=run.finished_at if run else None,
                last_run_entries_seen=run.entries_seen if run else None,
                last_run_scopes_failed=run.scopes_failed if run else None,
                reported_config=host.reported_config,
                desired_config=host.desired_config,
            )
        )
    return out


@router.get("/agents/config", response_model=None)
async def get_agent_desired_config(
    session: SessionDep, fingerprint: FingerprintDep
) -> Response | dict[str, object]:
    """Agent-facing (mTLS): THIS host's operator-set config override (ADR-033 #10), or 204 if none.

    The agent GETs this at run start, merges it over its local config, RE-VALIDATES the whole result
    against its own model, and applies it fail-safe (keeps the local config on any error). The host
    is the verified cert fingerprint, never a body (AR-0012).
    """
    host = (
        await session.execute(select(Host).where(Host.cert_fingerprint == fingerprint))
    ).scalar_one_or_none()
    if host is None or not host.desired_config:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return host.desired_config


@router.put("/agents/{host_id}/config", status_code=status.HTTP_204_NO_CONTENT)
async def set_agent_desired_config(
    host_id: int,
    override: AgentConfigOverrideIn,
    session: SessionDep,
    scope: ManageScopeDep,
    principal: PrincipalDep,
) -> Response:
    """Operator (MANAGE_AGENTS): set this host's config override (ADR-033 #10), audited.

    Shape-checked here (only the safe overridable fields; ``extra=forbid`` rejects identity/secret/
    write_enabled) and RE-VALIDATED by the owning agent, which applies it fail-safe on its next run.
    An empty/all-null body CLEARS the override. Scope-checked: a non-global principal can only
    target hosts it can manage.
    """
    stmt = select(Host).where(Host.id == host_id)
    if not scope.is_global:
        stmt = stmt.where(_host_scope_predicate(scope))
    host = (await session.execute(stmt)).scalar_one_or_none()
    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="host not found or out of scope"
        )
    desired = override.model_dump(exclude_none=True)
    before = host.desired_config
    host.desired_config = desired or None  # empty body clears the override
    chain = await build_persistent_chain(session)
    chain.append(
        actor=principal.subject,
        action="set_agent_config_override",
        target=host.name,
        before_state={"desired_config": before},
        result=("cleared" if not desired else "set"),
    )
    await session.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
