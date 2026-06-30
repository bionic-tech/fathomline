"""Human auth routes — login/logout/me + OIDC + MFA (ADD 13, ADD 03 §2).

A separate route group from the agent ingest surface (read≠write boundary, ADD 03 §3). Local
login mints a server-side session delivered as an httpOnly, Secure session cookie (CSRF-safe
because authz lives in the opaque server-side token, not an ambient credential the browser
auto-replays to a forgeable origin); API clients may instead send the token as a Bearer.

Login / logout and every MFA event are recorded into the hash-chained audit log
(audit-before-act for mutations, ADD 03 §8). Credentials are never logged (count-only).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.api.auth_deps import PrincipalDep
from fathom.api.deps import SessionDep, SettingsDep
from fathom.auth import mfa
from fathom.auth.models import MfaEnrollment, UserSession
from fathom.auth.principal import Capability, Principal, role_has
from fathom.auth.providers.local import SESSION_COOKIE, login
from fathom.auth.sessions import lookup_session, mark_step_up, revoke_session
from fathom.core.audit import AuditRecord
from fathom.core.audit_store import build_persistent_chain
from fathom.core.settings import Settings
from fathom.core.settings_store import RuntimeSettingsStore

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


async def _audit(
    session: AsyncSession, *, actor: str, action: str, target: str, result: str
) -> None:
    """Append an auth event to the durable, hash-chained audit log (ADD 03 §8).

    Wired to the persistent sink (was a no-op lambda, so ``auth.login`` / ``auth.mfa.*`` events
    were never queryable — EC-auth-27): each append stages an audit row on the request ``session``,
    committed with the request. Count-only — credentials never reach the log. Denied events (failed
    login / step-up) are committed explicitly by the caller *before* the 401 rolls the request
    back, so the security-relevant failures stay on the tamper-evident log too.
    """
    chain = await build_persistent_chain(session)
    chain.append(actor=actor, action=action, target=target, before_state={}, result=result)


def _settings_store(request: Request) -> RuntimeSettingsStore | None:
    """Return the runtime settings store off ``app.state`` (the encrypted secret backend), or None.

    Installed at startup (ADR-038); ``None`` only on a degraded boot. Reached the same way as the
    settings-admin routes. TOTP secrets are stored as named secrets here and resolved on verify.
    """
    store = getattr(request.app.state, "settings_store", None)
    return store if isinstance(store, RuntimeSettingsStore) else None


class LoginRequest(BaseModel):
    """Local username/password login (ADD 13 §1)."""

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class MeResponse(BaseModel):
    """The authenticated principal + its effective grants/scopes."""

    subject: str
    source: str
    display_name: str | None
    groups: list[str]
    grants: list[dict[str, object]]
    mfa_fresh: bool
    mfa_enrolled: bool = False  # a confirmed TOTP enrollment exists for this user


class MfaVerifyRequest(BaseModel):
    """A TOTP code for step-up / enrollment confirmation."""

    code: str = Field(min_length=6, max_length=8)


class EnrollResponse(BaseModel):
    """A pending TOTP enrollment (provisioning URI shown once; secret kept server-side)."""

    provisioning_uri: str


def _set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
        max_age=settings.session_ttl_seconds,
        path="/",
    )


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
async def post_login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
) -> Response:
    """Authenticate a local user and mint a session cookie (audited; no enumeration)."""
    client = request.client
    result = await login(
        session,
        username=body.username,
        password=body.password,
        ttl_seconds=settings.session_ttl_seconds,
        ip=client.host if client else None,
        user_agent=request.headers.get("User-Agent"),
    )
    if result is None:
        await _audit(
            session, actor=body.username, action="auth.login", target="local", result="denied"
        )
        await session.commit()  # persist the denied event before the 401 rolls the request back
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    _principal, token = result
    await _audit(
        session, actor=body.username, action="auth.login", target="local", result="granted"
    )
    _set_session_cookie(response, token, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def post_logout(principal: PrincipalDep, response: Response, session: SessionDep) -> Response:
    """Revoke the current session (instant lockout) and clear the cookie (audited)."""
    if principal.session_id is not None:
        row = await session.get(UserSession, principal.session_id)
        if row is not None:
            await revoke_session(session, row=row)
    await _audit(
        session, actor=principal.subject, action="auth.logout", target="session", result="granted"
    )
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=MeResponse)
async def get_me(
    principal: PrincipalDep, settings: SettingsDep, session: SessionDep
) -> MeResponse:
    """Return the authenticated principal and its effective grants/scopes."""
    enrolled = False
    if principal.user_id is not None:
        enrolled = (
            await session.scalar(
                select(MfaEnrollment.id)
                .where(
                    MfaEnrollment.user_id == principal.user_id,
                    MfaEnrollment.confirmed_at.is_not(None),
                )
                .limit(1)
            )
        ) is not None
    return MeResponse(
        subject=principal.subject,
        source=principal.source,
        display_name=principal.display_name,
        groups=list(principal.groups),
        grants=[
            {
                "role": g.role.value,
                "scope_kind": g.scope_kind,
                "host_id": g.host_id,
                "volume_id": g.volume_id,
            }
            for g in principal.grants
        ],
        mfa_fresh=mfa.is_step_up_fresh(
            principal.mfa_authenticated_at,
            freshness_seconds=settings.mfa_freshness_seconds,
        ),
        mfa_enrolled=enrolled,
    )


@router.post("/mfa/enroll", response_model=EnrollResponse)
async def post_mfa_enroll(
    principal: PrincipalDep, session: SessionDep, request: Request
) -> EnrollResponse:
    """Begin TOTP enrollment; the secret is encrypted at rest and only its reference persisted.

    P0b / ADR-010: the raw base32 secret is written to the runtime settings store (encrypted with
    the store's stable key, ADR-038) under a per-enrollment reference, and ``secret_ref`` holds
    only that reference — never the raw secret. If the store is somehow absent (a degraded boot)
    the secret falls back into ``secret_ref`` directly, which verify still accepts (legacy path).
    """
    secret = mfa.generate_secret()
    store = _settings_store(request)
    # (Re)enrolment replaces any prior TOTP for this user so verify always checks the just-issued
    # secret — exactly one enrollment row, never a stale duplicate. Drop the prior enrollment's
    # encrypted secret from the store too (best-effort) so re-enrolment doesn't orphan it; a legacy
    # raw secret_ref won't resolve there, so it's simply skipped (nothing to clean).
    prior = (
        (await session.execute(
            select(MfaEnrollment).where(MfaEnrollment.user_id == principal.user_id)
        ))
        .scalars()
        .all()
    )
    if store is not None:
        for row in prior:
            if store.resolve_secret(row.secret_ref) is not None:
                await store.clear_override(session, key=row.secret_ref)
    await session.execute(
        delete(MfaEnrollment).where(MfaEnrollment.user_id == principal.user_id)
    )
    # Persist the row first to mint its id, then key the encrypted secret by that id and store only
    # the reference. The raw value written here is transient (overwritten before commit when the
    # store is present), so the DB only ever commits the reference.
    enrollment = MfaEnrollment(user_id=principal.user_id, type="totp", secret_ref=secret)
    session.add(enrollment)
    await session.flush()
    if store is not None:
        ref = mfa.secret_ref_for(enrollment.id)
        await store.set_secret(session, ref=ref, value=secret, updated_by=principal.subject)
        enrollment.secret_ref = ref
    uri = mfa.provisioning_uri(secret, account=principal.subject)
    await _audit(
        session, actor=principal.subject, action="auth.mfa.enroll", target="totp", result="pending"
    )
    return EnrollResponse(provisioning_uri=uri)


@router.post("/mfa/verify", status_code=status.HTTP_204_NO_CONTENT)
async def post_mfa_verify(
    body: MfaVerifyRequest, principal: PrincipalDep, session: SessionDep, request: Request
) -> Response:
    """Verify a TOTP code and stamp step-up freshness on the session (ADD 13 §4)."""
    enrollment = (
        (
            await session.execute(
                select(MfaEnrollment).where(MfaEnrollment.user_id == principal.user_id)
            )
        )
        .scalars()
        .first()
    )
    # Resolve the secret through the encrypted store; a legacy enrollment whose secret_ref is the
    # raw secret won't resolve there, so resolve_enrollment_secret falls back to the ref itself.
    store = _settings_store(request)
    resolver: Callable[[str], str | None] = (
        store.resolve_secret if store is not None else (lambda _ref: None)
    )
    secret = (
        mfa.resolve_enrollment_secret(enrollment.secret_ref, resolver)
        if enrollment is not None
        else ""
    )
    if enrollment is None or not mfa.verify_totp(secret, body.code):
        await _audit(
            session, actor=principal.subject, action="auth.mfa.verify", target="totp",
            result="denied",
        )
        await session.commit()  # persist the denied step-up before the 401 rolls the request back
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid code")
    if enrollment.confirmed_at is None:
        enrollment.confirmed_at = datetime.now(tz=UTC)
    if principal.session_id is not None:
        row = await session.get(UserSession, principal.session_id)
        if row is not None:
            await mark_step_up(session, row=row)
    await _audit(
        session, actor=principal.subject, action="auth.mfa.verify", target="totp", result="granted"
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/oidc/login")
async def get_oidc_login(settings: SettingsDep) -> Response:
    """Begin the OIDC authorization-code + PKCE flow against authentik (ADD 03 §2.1).

    Returns 503 until the operator wires ``oidc_issuer`` / ``oidc_client_id`` and the client
    secret (via Docker secret / OpenBao, never in code — ADR-010). The full redirect +
    PKCE-challenge construction lands once the IdP wiring is configured; the SSRF-guarded
    discovery primitives already live in :mod:`fathom.auth.providers.oidc`.
    """
    if not settings.oidc_issuer or not settings.oidc_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC not configured",
        )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="OIDC interactive flow not yet enabled",
    )


@router.get("/oidc/callback")
async def get_oidc_callback(settings: SettingsDep) -> Response:
    """Complete the OIDC flow: validate the id_token, map groups→role, mint a session.

    Guarded the same way as :func:`get_oidc_login`; id_token validation
    (:func:`fathom.auth.providers.oidc.validate_id_token`) pins the signing-alg allow-list,
    issuer and audience to defeat alg-confusion / audience-substitution.
    """
    if not settings.oidc_issuer or not settings.oidc_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC not configured",
        )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="OIDC interactive flow not yet enabled",
    )


# Re-exported for callers/tests that introspect the audit + capability contract.
__all__ = [
    "AuditRecord",
    "Capability",
    "Principal",
    "lookup_session",
    "role_has",
    "router",
]
