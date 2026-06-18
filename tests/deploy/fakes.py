"""Shared test doubles for the deploy subsystem: a fake SSH layer + an in-test CA."""

from __future__ import annotations

import datetime as _dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.credentials import SshCredential
from fathom.core.deploy.ssh import CommandResult, SshClient


class FakeSshClient:
    """Records what the engine asked it to do; commands succeed unless matched by ``fail``."""

    def __init__(
        self, *, fingerprint: str = "SHA256:fakehostkey", fail: tuple[str, ...] = ()
    ) -> None:
        self.commands: list[tuple[str, bool]] = []
        self.written: dict[str, tuple[bytes, int]] = {}
        self.uploaded: list[tuple[str, str, int]] = []
        self.dirs: list[str] = []
        self.closed = False
        self._fingerprint = fingerprint
        self._fail = fail

    @property
    def host_key_fingerprint(self) -> str:
        return self._fingerprint

    async def run(self, command: str, *, sudo: bool = False) -> CommandResult:
        self.commands.append((command, sudo))
        if any(token in command for token in self._fail):
            return CommandResult(exit_status=1, stdout="", stderr="boom")
        return CommandResult(exit_status=0, stdout="true", stderr="")

    async def write_file(self, remote_path: str, content: bytes, *, mode: int = 0o644) -> None:
        self.written[remote_path] = (content, mode)

    async def upload_file(self, local_path: str, remote_path: str, *, mode: int = 0o644) -> None:
        self.uploaded.append((local_path, remote_path, mode))

    async def makedirs(self, remote_path: str, *, mode: int = 0o755) -> None:
        self.dirs.append(remote_path)

    async def close(self) -> None:
        self.closed = True


class FakeSshConnector:
    """Returns a configured :class:`FakeSshClient`, or raises to simulate an unreachable host."""

    def __init__(
        self, *, client: FakeSshClient | None = None, raise_on_connect: Exception | None = None
    ) -> None:
        self.client = client or FakeSshClient()
        self._raise = raise_on_connect
        self.connects: list[tuple[str, int]] = []

    async def connect(
        self,
        host: str,
        port: int,
        credential: SshCredential,
        *,
        expected_host_key: str | None = None,
    ) -> SshClient:
        self.connects.append((host, port))
        if self._raise is not None:
            raise self._raise
        # Faithfully model the real connector's TOFU check (ssh.py): a pinned key that does not
        # match the server's aborts the connect. Without this the fake would mask the enforcement.
        if expected_host_key is not None and expected_host_key != self.client.host_key_fingerprint:
            raise DeploymentError(
                f"host key fingerprint changed (expected {expected_host_key}, "
                f"got {self.client.host_key_fingerprint})"
            )
        return self.client


def make_test_ca() -> tuple[str, str]:
    """Build a throwaway RSA CA; return ``(cert_pem, key_pem)`` for minting in tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Fathom CA")])
    now = _dt.datetime.now(tz=_dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem
