"""Deploy-wizard live SSH browse: directory listing + df volume probe (ADR-034 Phase 2, Stage B)."""

from __future__ import annotations

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.certs import CertificateAuthority
from fathom.core.deploy.credentials import SshCredential
from fathom.core.deploy.engine import DeployEngine
from fathom.core.deploy.ssh import CommandResult, SshClient
from tests.deploy.fakes import FakeSshConnector, make_test_ca


class _ScriptedClient:
    """An SshClient whose ``run`` returns canned output keyed by a substring of the command."""

    def __init__(self, script: dict[str, CommandResult]) -> None:
        self._script = script
        self.closed = False
        self.commands: list[str] = []

    @property
    def host_key_fingerprint(self) -> str:
        return "SHA256:fake"

    async def run(self, command: str, *, sudo: bool = False) -> CommandResult:
        self.commands.append(command)
        for token, result in self._script.items():
            if token in command:
                return result
        return CommandResult(exit_status=0, stdout="", stderr="")

    async def write_file(self, remote_path: str, content: bytes, *, mode: int = 0o644) -> None: ...
    async def makedirs(self, remote_path: str, *, mode: int = 0o755) -> None: ...
    async def close(self) -> None:
        self.closed = True


def _ca() -> CertificateAuthority:
    cert_pem, key_pem = make_test_ca()
    return CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem)


def _engine(client: SshClient) -> DeployEngine:
    return DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)  # type: ignore[arg-type]


_CRED = SshCredential(username="root", password="pw")


async def test_browse_directory_parses_find_and_du() -> None:
    find_out = (
        "d\t4096\t1718500000.0\tsub\nf\t512\t1718500001.5\ttop.txt\nl\t10\t1718500002.0\tlink\n"
    )
    du_out = "150\t/scan/data/sub\n4096\t/scan/data\n"  # child first, then the parent (skipped)
    client = _ScriptedClient(
        {
            "find ": CommandResult(exit_status=0, stdout=find_out, stderr=""),
            "du -b": CommandResult(exit_status=0, stdout=du_out, stderr=""),
        }
    )
    res = await _engine(client).browse_directory(
        "1.2.3.4", 22, _CRED, path="/scan/data", expected_host_key="SHA256:fake"
    )
    assert res.error is None and res.truncated is False
    names = [e.name for e in res.entries]
    # dirs first; a symlink counts as not-a-dir, so link/top.txt sort alphabetically after sub
    assert names == ["sub", "link", "top.txt"]
    sub = next(e for e in res.entries if e.name == "sub")
    assert sub.is_dir and sub.subtree_size == 150 and sub.subtree_truncated is False
    assert sub.path == "/scan/data/sub"
    top = next(e for e in res.entries if e.name == "top.txt")
    assert not top.is_dir and top.size == 512 and top.subtree_size is None
    link = next(e for e in res.entries if e.name == "link")
    assert link.is_symlink and link.subtree_size is None  # symlinks never sized


async def test_browse_directory_marks_size_truncated_on_du_timeout() -> None:
    find_out = "d\t4096\t1.0\tbig\n"
    client = _ScriptedClient(
        {
            "find ": CommandResult(exit_status=0, stdout=find_out, stderr=""),
            # shell `timeout` kills du → exit 124, partial stdout
            "du -b": CommandResult(exit_status=124, stdout="999\t/scan/data/big\n", stderr=""),
        }
    )
    res = await _engine(client).browse_directory("1.2.3.4", 22, _CRED, path="/scan/data")
    big = next(e for e in res.entries if e.name == "big")
    assert big.subtree_size == 999 and big.subtree_truncated is True


async def test_browse_directory_connect_failure_returns_error() -> None:
    engine = DeployEngine(
        connector=FakeSshConnector(raise_on_connect=DeploymentError("unreachable")),
        ca=_ca(),
        cert_days=10,
    )
    res = await engine.browse_directory("1.2.3.4", 22, _CRED, path="/scan/data")
    assert res.entries == [] and res.error is not None and "unreachable" in res.error


async def test_probe_volumes_parses_df_and_skips_pseudo() -> None:
    df_out = (
        "Filesystem Type 1B-blocks Used Available Capacity Mounted on\n"
        "/dev/sda1 ext4 100 40 60 40% /\n"
        "tmpfs tmpfs 50 0 50 0% /run\n"
        "/dev/sdb1 xfs 200 10 190 5% /scan/data\n"
    )
    client = _ScriptedClient({"df ": CommandResult(exit_status=0, stdout=df_out, stderr="")})
    vols = await _engine(client).probe_volumes("1.2.3.4", 22, _CRED)
    mounts = {v.mountpoint: v for v in vols}
    assert "/run" not in mounts  # tmpfs skipped
    assert mounts["/"].fs_type == "ext4" and mounts["/"].total == 100
    assert mounts["/scan/data"].free == 190
