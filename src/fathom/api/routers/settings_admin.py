"""Runtime settings administration (ADR-038) — read/edit the in-app settings store.

Every route is gated by the ``MANAGE_SETTINGS`` capability (admin only — it is conferred solely by
the admin role). The non-secret read/edit routes need just that capability; the **secret** routes
(reveal a stored secret, store/clear a named secret) additionally require fresh step-up MFA, the
same posture as the other secret-bearing surfaces (deployment, remediation). Every value an operator
sets is validated through the pydantic settings model before it persists, so an out-of-range value
can never be stored, and secret values are encrypted at rest (Fernet) and only ever returned by the
explicit, step-up-gated reveal route.

The store lives on ``app.state.settings_store`` (installed at startup); these routes are inert
(503) if it is somehow absent. Changes take effect on the next request (live reload); a setting
whose effect is bound at startup is flagged ``restart_required`` so the operator knows to restart.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from fathom.api.auth_deps import PrincipalDep, require, require_step_up_mfa
from fathom.api.deps import SessionDep, SettingsDep
from fathom.api.schemas import (
    RevealSecretOut,
    SetSecretRequest,
    SetSettingRequest,
    SettingMutationResult,
    SettingOut,
    SettingsListOut,
)
from fathom.auth.mfa import is_step_up_fresh
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core.settings import Settings
from fathom.core.settings_store import (
    SETTING_POLICIES,
    RuntimeSettingsStore,
    SettingsStoreError,
)

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

# Admin-only (MANAGE_SETTINGS is conferred solely by the admin role). The ScopeFilter is unused —
# settings are estate-global — but resolving it keeps deny-by-default uniform across the app.
ManageSettingsDep = Annotated[ScopeFilter, Depends(require(Capability.MANAGE_SETTINGS))]

# Egress-endpoint settings: WHERE a stored credential is transmitted (the inference/embedding base
# URLs, the SMTP host/TLS, and the cloud-egress gate). Re-pointing one of these and then triggering
# a send would exfiltrate the resolved API key / SMTP password to an attacker-controlled host,
# bypassing the step-up MFA that guards ``/reveal`` — so changing them demands the same fresh
# step-up MFA as revealing a secret (security review: a non-fresh MANAGE_SETTINGS session, e.g. a
# stolen cookie, must not be able to redirect a credential off-host without an MFA challenge).
_EGRESS_SENSITIVE_SETTINGS: frozenset[str] = frozenset(
    {
        "inference_anthropic_url",
        "inference_openai_url",
        "inference_ollama_url",
        "concierge_embedding_url",
        "inference_allow_egress",
        "notify_email_smtp_host",
        "notify_email_use_tls",
    }
)


async def _require_step_up_for_egress(
    key: str, principal: PrincipalDep, settings: SettingsDep
) -> None:
    """Require fresh step-up MFA to change an egress-endpoint setting (_EGRESS_SENSITIVE_SETTINGS).

    For any other (non-egress) setting this is a no-op — those remain MANAGE_SETTINGS-only.
    """
    if key in _EGRESS_SENSITIVE_SETTINGS and not is_step_up_fresh(
        principal.mfa_authenticated_at, freshness_seconds=settings.mfa_freshness_seconds
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="step-up MFA required to change an egress endpoint",
        )


def _store(request: Request) -> RuntimeSettingsStore:
    store = getattr(request.app.state, "settings_store", None)
    if not isinstance(store, RuntimeSettingsStore):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="runtime settings store is not available",
        )
    return store


def _base(request: Request) -> Settings:
    base = getattr(request.app.state, "settings", None)
    assert isinstance(base, Settings)  # noqa: S101 — always set by create_app
    return base


@router.get("", response_model=SettingsListOut)
async def list_settings(request: Request, _scope: ManageSettingsDep) -> SettingsListOut:
    """Return every in-app-manageable setting with its effective value (secrets masked)."""
    store = _store(request)
    views = store.list_settings(_base(request))
    return SettingsListOut(
        settings=[
            SettingOut(
                key=v.key,
                category=v.category,
                type=v.type,
                editable=v.editable,
                is_secret=v.is_secret,
                restart_required=v.restart_required,
                help=v.help,
                overridden=v.overridden,
                is_set=v.is_set,
                value=v.value,
                label=v.label,
                options=v.options,
                suggestions=v.suggestions,
                relevant=v.relevant,
                relevant_hint=v.relevant_hint,
                advanced=v.advanced,
            )
            for v in views
        ],
        named_secrets=store.list_named_secrets(),
        version=store.version,
    )


@router.put("/secrets", response_model=SettingMutationResult)
async def set_named_secret(
    body: SetSecretRequest,
    request: Request,
    session: SessionDep,
    principal: PrincipalDep,
    _scope: ManageSettingsDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
) -> SettingMutationResult:
    """Store a free-form named secret (encrypted at rest) the secret provider resolves by name."""
    store = _store(request)
    try:
        await store.set_secret(
            session, ref=body.ref, value=body.value, updated_by=principal.subject
        )
    except SettingsStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    return SettingMutationResult(
        key=body.ref, overridden=True, restart_required=False, version=store.version
    )


@router.delete("/secrets/{ref}", response_model=SettingMutationResult)
async def clear_named_secret(
    ref: str,
    request: Request,
    session: SessionDep,
    _principal: PrincipalDep,
    _scope: ManageSettingsDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
) -> SettingMutationResult:
    """Delete a stored named secret. 404 if no such secret is set."""
    store = _store(request)
    if ref in Settings.model_fields:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="not a named secret")
    hit = await store.clear_override(session, key=ref)
    if not hit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such secret")
    return SettingMutationResult(
        key=ref, overridden=False, restart_required=False, version=store.version
    )


@router.put("/{key}", response_model=SettingMutationResult)
async def set_setting(
    key: str,
    body: SetSettingRequest,
    request: Request,
    session: SessionDep,
    principal: PrincipalDep,
    _scope: ManageSettingsDep,
    _egress_mfa: Annotated[None, Depends(_require_step_up_for_egress)],
) -> SettingMutationResult:
    """Set or update one setting's in-app override (validated; in-app value wins).

    Non-secret by classification, but an *egress-endpoint* key additionally requires fresh step-up
    MFA (``_require_step_up_for_egress``) — changing where a credential is sent is as sensitive as
    revealing it.
    """
    store = _store(request)
    try:
        await store.set_override(
            session,
            base=_base(request),
            key=key,
            value=body.value,
            updated_by=principal.subject,
        )
    except SettingsStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    policy = SETTING_POLICIES[key]
    return SettingMutationResult(
        key=key,
        overridden=True,
        restart_required=policy.restart_required,
        version=store.version,
    )


@router.delete("/{key}", response_model=SettingMutationResult)
async def clear_setting(
    key: str,
    request: Request,
    session: SessionDep,
    _principal: PrincipalDep,
    _scope: ManageSettingsDep,
) -> SettingMutationResult:
    """Reset a setting to its env/default value (delete the override). 404 if none was set."""
    store = _store(request)
    policy = SETTING_POLICIES.get(key)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown setting")
    hit = await store.clear_override(session, key=key)
    if not hit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no override set")
    return SettingMutationResult(
        key=key,
        overridden=False,
        restart_required=policy.restart_required,
        version=store.version,
    )


@router.post("/{key}/reveal", response_model=RevealSecretOut)
async def reveal_secret(
    key: str,
    request: Request,
    _principal: PrincipalDep,
    _scope: ManageSettingsDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
) -> RevealSecretOut:
    """Return the decrypted value of a stored secret (admin-only + fresh step-up MFA)."""
    store = _store(request)
    try:
        value = store.reveal(key)
    except SettingsStoreError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return RevealSecretOut(key=key, value=value)
