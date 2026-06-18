"""Argon2 password hashing for local users (ADD 03 §2; ADR-010 — hashes at rest only).

A thin wrapper over ``argon2-cffi`` with sane defaults. Hashes are stored at rest; raw
passwords are never logged (count-only credential logging). ``needs_rehash`` lets the local
login flow transparently upgrade a hash when the cost parameters change.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# argon2id with library defaults; tuned per-box at deploy time (ADD 13 risk note).
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Return an Argon2id hash (with embedded params + salt) for ``password``."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return whether ``password`` matches ``password_hash`` (constant-time via argon2-cffi)."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Return whether ``password_hash`` was produced with stale cost parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
