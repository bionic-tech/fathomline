"""TOTP second factor + step-up freshness (ADD 13 §4, ADD 03 §6).

Local second factor is TOTP (``pyotp``). The TOTP secret itself lives in the secret backend
(ADR-010); only a *reference* is stored in :class:`fathom.auth.models.MfaEnrollment`. The
secret is resolved through a pluggable lookup so tests and deployments can inject their own
backend (env / Docker secret / OpenBao) without touching this module.

Step-up freshness: write routes consume :func:`is_step_up_fresh`, which compares the
server-stored ``mfa_authenticated_at`` against the configured window (default 300s). For
forward-auth / OIDC principals an upstream ``amr``/``acr`` step-up claim may satisfy this
instead (see :func:`fathom.api.auth_deps.require_step_up_mfa`); absent that, a local TOTP
step-up is required.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pyotp

# Default freshness window for step-up MFA (ADD 13 §4 / ADD 03 §6). Overridable via settings.
DEFAULT_FRESHNESS_SECONDS = 300


def generate_secret() -> str:
    """Return a fresh base32 TOTP secret (stored in the secret backend, never the DB)."""
    return pyotp.random_base32()


def secret_ref_for(enrollment_id: int) -> str:
    """Settings-store reference under which an enrollment's TOTP secret is stored (P0b / ADR-010).

    The raw base32 secret is encrypted at rest in the runtime settings store (ADR-038) under this
    stable, per-enrollment name; only the name lands in ``MfaEnrollment.secret_ref`` — never the
    secret itself.
    """
    return f"mfa:{enrollment_id}"


def resolve_enrollment_secret(
    secret_ref: str, resolver: Callable[[str], str | None]
) -> str:
    """Resolve an enrollment's TOTP secret from its ``secret_ref`` (legacy raw secret as fallback).

    Hardened enrollments (P0b) keep only a *reference* in ``secret_ref`` and the encrypted base32
    secret in the settings store; ``resolver`` (the store's ``resolve_secret``) returns the
    decrypted secret for such a reference. A LEGACY enrollment (pre-hardening) instead holds the
    raw base32 secret directly in ``secret_ref`` — there the resolver returns ``None`` and we treat
    ``secret_ref`` itself as the secret, so existing plaintext enrollments keep verifying until the
    user re-enrolls (which then stores the secret encrypted). No bulk migration of live secrets.
    """
    resolved = resolver(secret_ref)
    return resolved if resolved is not None else secret_ref


def provisioning_uri(secret: str, *, account: str, issuer: str = "Fathom") -> str:
    """Return an ``otpauth://`` URI for enrolling an authenticator app."""
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def verify_totp(secret: str, code: str, *, valid_window: int = 1) -> bool:
    """Verify a TOTP ``code`` against ``secret`` (±``valid_window`` steps for clock drift)."""
    if not code or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=valid_window)


def is_step_up_fresh(
    mfa_authenticated_at: datetime | None,
    *,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    now: datetime | None = None,
) -> bool:
    """Return whether a step-up MFA at ``mfa_authenticated_at`` is still fresh (fail-closed)."""
    if mfa_authenticated_at is None:
        return False
    current = now or datetime.now(tz=UTC)
    # Normalise naive timestamps (SQLite round-trips can drop tzinfo) to UTC.
    stamped = (
        mfa_authenticated_at
        if mfa_authenticated_at.tzinfo is not None
        else mfa_authenticated_at.replace(tzinfo=UTC)
    )
    return current - stamped <= timedelta(seconds=freshness_seconds)
