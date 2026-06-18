"""SSH transport for push deploys (ADR-026 §push), behind a Protocol so the engine is testable.

The engine talks to :class:`SshClient` / :class:`SshConnector` — small interfaces covering exactly
what a deploy needs: run a command (optionally via ``sudo -S``), write a file, make a directory,
and read the server host-key fingerprint for TOFU. :class:`AsyncSshClient` is the real,
asyncssh-backed implementation; tests inject a fake connector and never touch a socket.

Host-key policy (ADR-026 §host-key): on first contact the server key fingerprint is captured and
returned for the operator to accept; if an ``expected_host_key`` fingerprint is supplied it must
match or the connect aborts. There is no blind auto-add.
"""

from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.credentials import SshCredential
from fathom.logging import get_logger

if TYPE_CHECKING:
    import asyncssh

_log = get_logger("fathom.core.deploy.ssh")


def wrap_sudo(command: str, *, password: str | None) -> tuple[str, str | None]:
    """Build the sudo-wrapped command string + optional stdin for :meth:`SshClient.run`.

    The command is run through ``bash -c`` so compound commands (``cd X && docker compose ...``)
    work — ``sudo -n cd ...`` fails because ``cd`` is a shell builtin, not a binary. Passwordless
    sudo uses ``-n``; otherwise the password is fed to ``sudo -S`` on stdin.
    """
    wrapped = f"bash -c {shlex.quote(command)}"
    if password is None:
        return f"sudo -n {wrapped}", None
    return f"sudo -S -p '' {wrapped}", password + "\n"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """The outcome of one remote command."""

    exit_status: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_status == 0


class SshClient(Protocol):
    """A live SSH session to one target (close it when done)."""

    @property
    def host_key_fingerprint(self) -> str:
        """The server host-key SHA-256 fingerprint captured at connect (for TOFU)."""
        ...

    async def run(self, command: str, *, sudo: bool = False) -> CommandResult:
        """Run ``command``; with ``sudo`` wrap it in ``sudo -S`` fed the sudo password."""
        ...

    async def write_file(self, remote_path: str, content: bytes, *, mode: int = 0o644) -> None:
        """Write ``content`` to ``remote_path`` (parent dir must exist), then chmod to ``mode``."""
        ...

    async def upload_file(self, local_path: str, remote_path: str, *, mode: int = 0o644) -> None:
        """Stream a local file to ``remote_path`` (chunked SFTP, not held in memory)."""
        ...

    async def makedirs(self, remote_path: str, *, mode: int = 0o755) -> None:
        """Create ``remote_path`` and any missing parents (idempotent)."""
        ...

    async def close(self) -> None:
        """Close the session."""
        ...


class SshConnector(Protocol):
    """Opens :class:`SshClient` sessions. Injectable so the engine never needs a real host."""

    async def connect(
        self,
        host: str,
        port: int,
        credential: SshCredential,
        *,
        expected_host_key: str | None = None,
    ) -> SshClient:
        """Open a session to ``host:port`` with ``credential`` (TOFU-checked vs expected key)."""
        ...


class AsyncSshClient:
    """Real asyncssh-backed :class:`SshClient`. Not unit-tested — covered by the live smoke test."""

    def __init__(
        self,
        conn: asyncssh.SSHClientConnection,
        *,
        sudo_password: str | None,
        command_timeout_s: float = 600.0,
    ) -> None:
        self._conn = conn
        self._sudo_password = sudo_password
        self._command_timeout_s = command_timeout_s
        host_key = conn.get_server_host_key()
        self._fingerprint = host_key.get_fingerprint() if host_key is not None else "unknown"

    @property
    def host_key_fingerprint(self) -> str:  # pragma: no cover - needs a live server
        return self._fingerprint

    async def run(self, command: str, *, sudo: bool = False) -> CommandResult:  # pragma: no cover
        cmd, stdin = wrap_sudo(command, password=self._sudo_password) if sudo else (command, None)
        try:
            # A generous per-command timeout so a wedged remote command (e.g. a stuck docker call)
            # cannot pin a deploy slot indefinitely — connect/login timeouts only bound the connect
            # (round-6 P3). All deploy commands are quick (the image is loaded from a local file).
            result = await asyncio.wait_for(
                self._conn.run(cmd, input=stdin, check=False), timeout=self._command_timeout_s
            )
        except TimeoutError:
            return CommandResult(
                exit_status=-1, stdout="", stderr=f"command timed out ({self._command_timeout_s}s)"
            )
        return CommandResult(
            exit_status=result.exit_status if result.exit_status is not None else -1,
            stdout=_as_text(result.stdout),
            stderr=_as_text(result.stderr),
        )

    async def makedirs(self, remote_path: str, *, mode: int = 0o755) -> None:  # pragma: no cover
        async with self._conn.start_sftp_client() as sftp:
            await sftp.makedirs(remote_path, exist_ok=True)
            await sftp.chmod(remote_path, mode)

    async def write_file(
        self, remote_path: str, content: bytes, *, mode: int = 0o644
    ) -> None:  # pragma: no cover
        async with self._conn.start_sftp_client() as sftp:
            async with sftp.open(remote_path, "wb") as fh:
                await fh.write(content)
            await sftp.chmod(remote_path, mode)

    async def upload_file(
        self, local_path: str, remote_path: str, *, mode: int = 0o644
    ) -> None:  # pragma: no cover
        async with self._conn.start_sftp_client() as sftp:
            await sftp.put(local_path, remote_path)  # chunked stream, not held in memory
            await sftp.chmod(remote_path, mode)

    async def close(self) -> None:  # pragma: no cover
        self._conn.close()
        await self._conn.wait_closed()


def _as_text(value: object) -> str:  # pragma: no cover - thin asyncssh adapter
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value) if value is not None else ""


class AsyncSshConnector:
    """Real connector: builds an asyncssh connection from a :class:`SshCredential`.

    ``connect_timeout`` bounds both the TCP/SSH handshake and the auth phase so a hung or
    silently-dropping target cannot pin a deploy slot indefinitely (threat-model D-2).
    """

    def __init__(self, *, connect_timeout: float = 20.0) -> None:
        self._connect_timeout = connect_timeout

    async def connect(
        self,
        host: str,
        port: int,
        credential: SshCredential,
        *,
        expected_host_key: str | None = None,
    ) -> SshClient:  # pragma: no cover - needs a live host (Friday smoke test)
        import asyncssh

        credential.validate()
        client_keys: list[object] = []
        if credential.private_key is not None:
            try:
                key = asyncssh.import_private_key(credential.private_key, credential.passphrase)
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise DeploymentError(f"could not load SSH private key: {exc}") from exc
            if credential.certificate is not None:
                try:
                    cert = asyncssh.import_certificate(credential.certificate)
                except (asyncssh.KeyImportError, ValueError) as exc:
                    raise DeploymentError("could not load SSH certificate") from exc
                client_keys.append((key, cert))
            else:
                client_keys.append(key)
        try:
            conn = await asyncssh.connect(
                host,
                port=port,
                username=credential.username,
                client_keys=client_keys or None,
                password=credential.password,
                known_hosts=None,  # TOFU enforced explicitly below; never a blind auto-add
                connect_timeout=self._connect_timeout,
                login_timeout=self._connect_timeout,
            )
        except (OSError, asyncssh.Error) as exc:
            raise DeploymentError(f"SSH connect to {host}:{port} failed: {exc}") from exc
        client = AsyncSshClient(conn, sudo_password=credential.sudo_password)
        if expected_host_key is not None and client.host_key_fingerprint != expected_host_key:
            await client.close()
            raise DeploymentError(
                "host key fingerprint changed — refusing to deploy "
                f"(expected {expected_host_key}, got {client.host_key_fingerprint})"
            )
        _log.info(
            "ssh session established",
            extra={"host": host, "port": port, "auth": credential.auth_kind()},
        )
        return client
