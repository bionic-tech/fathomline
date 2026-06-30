"""Suitability read surface (ADR-037) — per-host AI-option traffic-lights + a recommendation.

Read-only, ``VIEW_METADATA`` + scope gated. For each in-scope host it feeds the host's reported
hardware facts (``host.facts``, ADR-037) to the pure suitability engine and returns ✅/⚠️/❌ per AI
option plus one "best for you" pick. The cloud egress flag (which decides whether a cloud
recommendation is even on the table) comes from the effective settings, so it tracks the runtime
settings store live. No I/O beyond reading the host rows; the engine sends nothing off-host.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select

from fathom.api.auth_deps import require
from fathom.api.deps import SessionDep, SettingsDep
from fathom.api.routers.agents import _host_scope_predicate
from fathom.api.schemas import (
    HostFactsOut,
    HostSuitabilityOut,
    OptionAssessmentOut,
    SuitabilityListOut,
)
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.models import Host
from fathom.core.suitability import HostFacts, assess

router = APIRouter(prefix="/api/v1", tags=["suitability"])

ViewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]


def _facts_from_json(raw: dict[str, object] | None) -> HostFacts:
    if not raw:
        return HostFacts()
    return HostFacts(
        cpu_cores=_as_int(raw.get("cpu_cores")),
        cpu_model=_as_str(raw.get("cpu_model")),
        ram_bytes=_as_int(raw.get("ram_bytes")),
        gpu_name=_as_str(raw.get("gpu_name")),
        gpu_vram_bytes=_as_int(raw.get("gpu_vram_bytes")),
        arch=_as_str(raw.get("arch")),
    )


def _as_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


@router.get("/suitability", response_model=SuitabilityListOut)
async def get_suitability(
    session: SessionDep, settings: SettingsDep, scope: ViewScopeDep
) -> SuitabilityListOut:
    """Assess every in-scope host against the AI options (traffic-lights + a recommendation)."""
    stmt = select(Host).order_by(Host.id)
    if not scope.is_global:
        stmt = stmt.where(_host_scope_predicate(scope))
    hosts = (await session.execute(stmt)).scalars().all()
    egress = settings.inference_allow_egress
    out: list[HostSuitabilityOut] = []
    for host in hosts:
        facts = _facts_from_json(host.facts)
        result = assess(facts, egress_allowed=egress)
        out.append(
            HostSuitabilityOut(
                host_id=host.id,
                name=host.name,
                facts_known=result.facts_known,
                facts=HostFactsOut(**vars(facts)) if result.facts_known else None,
                options=[
                    OptionAssessmentOut(key=o.key, label=o.label, rating=o.rating, reason=o.reason)
                    for o in result.options
                ],
                recommendation=result.recommendation,
                recommended_chat_provider=result.recommended_chat_provider,
                recommended_chat_model=result.recommended_chat_model,
                recommended_embedder=result.recommended_embedder,
                recommended_embedding_dim=result.recommended_embedding_dim,
            )
        )
    return SuitabilityListOut(hosts=out, egress_allowed=egress)
