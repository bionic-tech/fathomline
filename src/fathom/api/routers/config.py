"""Server-config read surface — the non-secret feature flags, for the Settings page (read-only).

Fathom's feature gates (Organize, the LLM provider, remediation, preview…) are deliberately
**server config (environment variables)**, not in-app toggles — flipping "let the app move/delete
files" from a browser would be the wrong trust boundary. But operators still want to *see* the
current configuration, so this exposes a **curated, secret-free** view of those flags. It NEVER
returns a secret: no keys, key references, the DB URL, signing material, or cookie/proxy secrets —
only booleans, model names, the inference URL, and numeric limits. Gated by ``VIEW_METADATA``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from fathom.api.auth_deps import require
from fathom.api.deps import SettingsDep
from fathom.api.schemas import ServerConfigOut
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter

router = APIRouter(prefix="/api/v1", tags=["config"])

ConfigScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]


@router.get("/config", response_model=ServerConfigOut)
async def get_server_config(settings: SettingsDep, _scope: ConfigScopeDep) -> ServerConfigOut:
    """Return the non-secret server feature flags (read-only; env-controlled)."""
    return ServerConfigOut(
        organize_enabled=settings.organize_enabled,
        inference_provider=settings.inference_provider,
        inference_model=settings.inference_model,
        inference_ollama_url=settings.inference_ollama_url,
        organize_model=settings.organize_model,
        inference_allow_egress=settings.inference_allow_egress,
        inference_timeout_seconds=settings.inference_timeout_seconds,
        remediation_enabled=settings.remediation_enabled,
        remediation_blast_cap=settings.remediation_blast_cap,
        preview_enabled=settings.preview_enabled,
        change_log_retention_days=settings.change_log_retention_days,
        concierge_enabled=settings.concierge_enabled,
        concierge_model=settings.concierge_model,
        concierge_embeddings_enabled=settings.concierge_embeddings_enabled,
        scan_coordinator_enabled=settings.scan_coordinator_enabled,
        notifications_enabled=settings.notifications_enabled,
        onboarding_completed=settings.onboarding_completed,
    )
