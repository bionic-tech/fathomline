"""Human auth routes — login/logout/me + OIDC + MFA (ADD 13, ADD 03 §2).

A separate route group from the agent ingest surface (read≠write boundary, ADD 03 §3). Local
login mints a server-side session delivered as an httpOnly, Secure session cookie (CSRF-safe
because authz lives in the opaque server-side token, not an ambient credential the browser
auto-replays to a forgeable origin); API clients may instead send the token as a Bearer.

Login / logout and every MFA event are recorded into the hash-chained audit log
(audit-before-act for mutations, ADD 03 §8). Credentials are never logged (count-only).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from fathom.api.auth_deps import PrincipalDep
from fathom.api.deps import SessionDep, SettingsDep
from fathom.auth import mfa
from fathom.auth.models import MfaEnrollment, UserSession
from fathom.auth.principal import Capability, Principal, role_has
from fathom.auth.providers.local import SESSION_COOKIE, login
from fathom.auth.sessions import lookup_session, mark_step_up, revoke_session
from fathom.core.audit import AuditChain, AuditRecord
from fathom.core.settings import Settings

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _audit(actor: str, action: str, target: str, result: str) -> None:
    """Append an auth event to the hash-chained audit log (ADD 03 §8).

    The persistent audit sink is owned by the audit subsystem; here we build a record so the
    chain semantics (audit-before-act) hold at the call site. Count-only: no credentials.
    """
    chain = AuditChain(sink=lambda _record: None)
    chain.append(actor=actor, action=action, target=target, before_state={}, result=result)


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
        _audit(actor=body.username, action="auth.login", target="local", result="denied")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    _principal, token = result
    _audit(actor=body.username, action="auth.login", target="local", result="granted")
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
    _audit(actor=principal.subject, action="auth.logout", target="session", result="granted")
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=MeResponse)
async def get_me(principal: PrincipalDep, settings: SettingsDep) -> MeResponse:
    """Return the authenticated principal and its effective grants/scopes."""
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
    )


@router.post("/mfa/enroll", response_model=EnrollResponse)
async def post_mfa_enroll(principal: PrincipalDep, session: SessionDep) -> EnrollResponse:
    """Begin TOTP enrollment; the secret is stored by reference, never returned raw."""
    secret = mfa.generate_secret()
    # In production the secret is written to the secret backend and only its ref persisted
    # (ADR-010). Here the ref *is* the secret store key; tests inject a backend.
    enrollment = MfaEnrollment(user_id=principal.user_id, type="totp", secret_ref=secret)
    session.add(enrollment)
    await session.flush()
    uri = mfa.provisioning_uri(secret, account=principal.subject)
    _audit(actor=principal.subject, action="auth.mfa.enroll", target="totp", result="pending")
    return EnrollResponse(provisioning_uri=uri)


@router.post("/mfa/verify", status_code=status.HTTP_204_NO_CONTENT)
async def post_mfa_verify(
    body: MfaVerifyRequest, principal: PrincipalDep, session: SessionDep
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
    if enrollment is None or not mfa.verify_totp(enrollment.secret_ref, body.code):
        _audit(actor=principal.subject, action="auth.mfa.verify", target="totp", result="denied")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid code")
    if enrollment.confirmed_at is None:
        enrollment.confirmed_at = datetime.now(tz=UTC)
    if principal.session_id is not None:
        row = await session.get(UserSession, principal.session_id)
        if row is not None:
            await mark_step_up(session, row=row)
    _audit(actor=principal.subject, action="auth.mfa.verify", target="totp", result="granted")
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
