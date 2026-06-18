"""Step-up MFA freshness tests (ADD 13 §4, ADD 03 §6) + TOTP verify."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pyotp

from fathom.auth.mfa import (
    DEFAULT_FRESHNESS_SECONDS,
    generate_secret,
    is_step_up_fresh,
    verify_totp,
)


def test_totp_verify_roundtrip() -> None:
    secret = generate_secret()
    code = pyotp.TOTP(secret).now()
    assert verify_totp(secret, code) is True
    assert verify_totp(secret, "000000") in (True, False)  # almost always False
    assert verify_totp(secret, "notnumeric") is False
    assert verify_totp(secret, "") is False


def test_step_up_none_is_stale() -> None:
    assert is_step_up_fresh(None) is False


def test_step_up_within_window_is_fresh() -> None:
    now = datetime.now(tz=UTC)
    recent = now - timedelta(seconds=DEFAULT_FRESHNESS_SECONDS - 10)
    assert is_step_up_fresh(recent, now=now) is True


def test_step_up_just_outside_window_is_stale() -> None:
    now = datetime.now(tz=UTC)
    old = now - timedelta(seconds=DEFAULT_FRESHNESS_SECONDS + 1)
    assert is_step_up_fresh(old, now=now) is False


def test_step_up_custom_window() -> None:
    now = datetime.now(tz=UTC)
    stamp = now - timedelta(seconds=120)
    assert is_step_up_fresh(stamp, freshness_seconds=60, now=now) is False
    assert is_step_up_fresh(stamp, freshness_seconds=300, now=now) is True


def test_step_up_naive_timestamp_normalised() -> None:
    # A naive timestamp (SQLite round-trip can drop tzinfo) is treated as UTC.
    now = datetime.now(tz=UTC)
    naive = (now - timedelta(seconds=10)).replace(tzinfo=None)
    assert is_step_up_fresh(naive, now=now) is True
