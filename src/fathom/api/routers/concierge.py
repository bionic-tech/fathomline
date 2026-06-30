"""Concierge router (ADR-035) — natural-language Q&A over the catalogue (read-only).

``POST /api/v1/concierge/ask`` is **read-only**: it classifies the question to one closed-enum
tool, runs the matching scope-enforcing catalogue query, and narrates the result. It mutates
nothing, the model has no authority (it only picks a tool + params), and every result is bounded by
the server-authoritative :class:`ScopeFilter`. Gated by ``VIEW_METADATA`` + scope, default-OFF
behind ``concierge_enabled``. A cloud provider (Anthropic/OpenAI) is only constructed when the
inference egress gate is explicitly open (ADR-022) — the default local Ollama path sends nothing
off-host.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from fathom.api.auth_deps import require
from fathom.api.deps import SecretProviderDep, SessionDep, SettingsDep
from fathom.api.schemas import (
    ConciergeActionOut,
    ConciergeAnswerOut,
    ConciergeAskRequest,
    ConciergeCitationOut,
)
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import query
from fathom.core.concierge import ConciergeService
from fathom.core.concierge.service import ConciergeTool
from fathom.inference import InferenceError, build_inference_provider
from fathom.inference.embeddings import build_embedding_provider
from fathom.logging import get_logger

_log = get_logger("fathom.api.routers.concierge")

router = APIRouter(prefix="/api/v1", tags=["concierge"])

ConciergeScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]


@router.post("/concierge/ask", response_model=ConciergeAnswerOut)
async def concierge_ask(
    body: ConciergeAskRequest,
    session: SessionDep,
    settings: SettingsDep,
    secret_provider: SecretProviderDep,
    scope: ConciergeScopeDep,
) -> ConciergeAnswerOut:
    """Answer a natural-language storage question (read-only; scope-enforced)."""
    if not settings.concierge_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="concierge is disabled (concierge_enabled=False)",
        )
    # If a volume hint is supplied, prove scope on it up front (403 out-of-scope) so the hint can
    # never widen what the principal may see (the queries also scope-filter regardless).
    if body.volume_id is not None:
        volume = await query.get_volume_in_scope(session, body.volume_id, scope)
        if volume is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown volume")

    # A /command may force a specific tool (deterministic, no LLM classify). Validate it to the
    # closed enum — an unknown tool is a 422, never a silent fallback.
    forced_tool: ConciergeTool | None = None
    if body.tool:
        try:
            forced_tool = ConciergeTool(body.tool)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"unknown concierge tool {body.tool!r}",
            ) from exc

    try:
        # One cohesive model: the per-feature override if set, else the global inference_model.
        chat_model = settings.concierge_model or settings.inference_model
        provider = build_inference_provider(
            settings, model=chat_model, secret_provider=secret_provider
        )
        # The query embedder (semantic_search) is built only when embeddings are on; a build failure
        # (e.g. cloud embedder without egress/key) leaves it None and semantic search degrades to
        # substring find rather than failing the ask.
        embedding_provider = None
        if settings.concierge_embeddings_enabled:
            try:
                embedding_provider = build_embedding_provider(
                    settings, secret_provider=secret_provider
                )
            except InferenceError:
                embedding_provider = None
        service = ConciergeService(
            session,
            provider,
            model=chat_model,
            context_max_rows=settings.concierge_context_max_rows,
            embeddings_enabled=settings.concierge_embeddings_enabled,
            embedding_provider=embedding_provider,
        )
        result = await service.ask(
            body.question,
            scope=scope,
            volume_id=body.volume_id,
            host_id=body.host_id,
            page=body.page,
            history=[(t.role, t.content) for t in body.history],
            forced_tool=forced_tool,
        )
    except InferenceError as exc:
        # Sanitised mapping — no provider internals leak; the read path changed nothing.
        raise HTTPException(status_code=exc.status_code, detail="inference unavailable") from exc

    return ConciergeAnswerOut(
        answer=result.answer,
        tool=result.tool,
        considered=result.considered,
        citations=[
            ConciergeCitationOut(
                label=c.label,
                path=c.path,
                entry_id=c.entry_id,
                host_id=c.host_id,
                volume_id=c.volume_id,
            )
            for c in result.citations
        ],
        actions=[
            ConciergeActionOut(label=a.label, route=a.route, volume_id=a.volume_id)
            for a in result.actions
        ],
    )
