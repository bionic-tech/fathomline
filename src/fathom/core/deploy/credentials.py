"""Transient SSH credentials for a push deploy (ADR-026 §SSH auth).

Every field here is a **secret in flight**: supplied by the operator for one deploy, used in
memory, and dropped. Nothing in this module is persisted, serialised, or logged — ``__repr__`` is
redacted so a credential can never leak into a stack trace or a structured log ``extra``. The
supported auth methods mirror the wizard: SSH private key (with optional passphrase), an optional
OpenSSH user certificate for that key, plain username+password, and a separate optional sudo
password for hosts without passwordless sudo.
"""

from __future__ import annotations

from dataclasses import dataclass

from fathom.core.deploy import DeploymentError


@dataclass(frozen=True, slots=True)
class SshCredential:
    """One target's SSH login material (transient; redacted repr).

    Exactly one *primary* auth method must be present: a ``private_key`` PEM (optionally
    passphrase-protected, optionally accompanied by an OpenSSH ``certificate``) **or** a
    ``password``. ``sudo_password`` is independent — it is fed to ``sudo -S`` on hosts that do not
    grant passwordless sudo, and is never the SSH auth itself.
    """

    username: str
    private_key: str | None = None
    passphrase: str | None = None
    certificate: str | None = None
    password: str | None = None
    sudo_password: str | None = None

    def __repr__(self) -> str:  # pragma: no cover - trivial, but security-relevant
        """Redacted repr — secret fields render as presence flags, never values."""
        return (
            "SshCredential("
            f"username={self.username!r}, "
            f"auth={self.auth_kind()}, "
            f"passphrase={'<set>' if self.passphrase else None}, "
            f"sudo_password={'<set>' if self.sudo_password else None})"
        )

    def auth_kind(self) -> str:
        """Return the primary auth method (``key``, ``key+cert``, ``password``, or ``none``)."""
        if self.private_key is not None:
            return "key+cert" if self.certificate is not None else "key"
        if self.password is not None:
            return "password"
        return "none"

    def validate(self) -> None:
        """Raise :class:`DeploymentError` unless exactly one usable primary auth method is set.

        A passphrase or a certificate without a private key is a misconfiguration (nothing to
        decrypt / nothing to present), and so is supplying both a key and a password.
        """
        if not self.username:
            raise DeploymentError("ssh credential requires a username")
        has_key = self.private_key is not None
        has_password = self.password is not None
        if has_key and has_password:
            raise DeploymentError("ssh credential has both a key and a password (pick one)")
        if not has_key and not has_password:
            raise DeploymentError("ssh credential needs a private key or a password")
        if not has_key and (self.passphrase is not None or self.certificate is not None):
            raise DeploymentError("passphrase/certificate provided without a private key")
