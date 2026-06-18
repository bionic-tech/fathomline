"""Pull-mode enrollment (ADR-026 §Mode B).

Instead of core SSHing out, it issues a **single-use, short-TTL** enrollment token and shows a
one-line bootstrap command. The operator runs it on the target; the target redeems the token over
the existing HTTPS boundary to fetch its bundle and self-installs. Tokens are opaque bearer
secrets validated **server-side** (hash stored, single-use, TTL) — the same model as session
tokens, so a leaked token is bounded by its short life and one-shot redemption.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.bundle import BundleSpec
from fathom.core.deploy.winbundle import WindowsBundleSpec

_TOKEN_BYTES = 32

# The agent platforms an enrollment can target (ADR-026 Linux/Docker; ADR-027 W1 Windows).
PLATFORM_LINUX: Final = "linux"
PLATFORM_WINDOWS: Final = "windows"


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class EnrollmentGrant:
    """A pending pull enrollment: which host, what to scan, when it expires, whether it's spent.

    ``platform`` selects the bundle shape at redeem time: ``linux`` → the Docker bundle (tar.gz),
    ``windows`` → the native W1 bundle (zip). ``spec`` is the matching spec type for that platform.
    """

    host_id: str
    spec: BundleSpec | WindowsBundleSpec
    expires_at: datetime
    redeemed: bool = False
    platform: str = PLATFORM_LINUX


class EnrollmentRegistry:
    """In-memory store of pending enrollment tokens (single-use, TTL; core is single-worker)."""

    def __init__(
        self,
        *,
        ttl_seconds: int,
        max_pending: int = 1000,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_pending = max_pending
        self._now = now or (lambda: datetime.now(tz=UTC))
        self._grants: dict[str, EnrollmentGrant] = {}

    def issue(
        self,
        host_id: str,
        spec: BundleSpec | WindowsBundleSpec,
        *,
        platform: str = PLATFORM_LINUX,
    ) -> tuple[str, datetime]:
        """Mint a one-time token for ``host_id``; returns ``(raw_token, expires_at)``.

        The raw token is shown to the operator once (it goes in the bootstrap command); only its
        hash is retained. Issuing first garbage-collects expired/spent grants, then refuses over
        ``max_pending`` live tokens so a buggy issue-loop cannot grow memory unboundedly (round-5).
        ``platform`` is recorded on the grant so redeem renders the right bundle shape (ADR-027).
        """
        self._gc()
        if len(self._grants) >= self._max_pending:
            raise DeploymentError("too many pending enrollment tokens; retry shortly")
        raw = secrets.token_urlsafe(_TOKEN_BYTES)
        expires = self._now() + timedelta(seconds=self._ttl)
        self._grants[_hash_token(raw)] = EnrollmentGrant(
            host_id=host_id, spec=spec, expires_at=expires, platform=platform
        )
        return raw, expires

    def verify(self, raw_token: str) -> EnrollmentGrant:
        """Return the grant for a live token **without consuming it** (fail-closed).

        Used by the non-secret image-archive fetch, which a bootstrap may call before redeeming the
        token for its (secret) bundle. The token must still be live — unknown/used/expired is
        refused — but a successful verify leaves it spendable exactly once by :meth:`redeem`.

        Raises:
            DeploymentError: the token is unknown, already redeemed, or expired.
        """
        key = _hash_token(raw_token)
        grant = self._grants.get(key)
        if grant is None or grant.redeemed:
            raise DeploymentError("enrollment token is invalid")
        if self._now() >= grant.expires_at:
            del self._grants[key]
            raise DeploymentError("enrollment token expired")
        return grant

    def redeem(self, raw_token: str) -> EnrollmentGrant:
        """Consume ``raw_token`` and return its grant (single-use).

        Raises:
            DeploymentError: the token is unknown, already redeemed, or expired (fail-closed). A
                redeemed/expired grant is dropped so it can never be replayed.
        """
        key = _hash_token(raw_token)
        grant = self._grants.get(key)
        if grant is None:
            raise DeploymentError("enrollment token is invalid")
        if grant.redeemed:
            raise DeploymentError("enrollment token already used")
        if self._now() >= grant.expires_at:
            del self._grants[key]
            raise DeploymentError("enrollment token expired")
        grant.redeemed = True
        del self._grants[key]  # single-use: gone the moment it is spent
        return grant

    def _gc(self) -> None:
        now = self._now()
        for key in [k for k, g in self._grants.items() if g.redeemed or now >= g.expires_at]:
            del self._grants[key]

    def pending_count(self) -> int:
        """Number of live (unspent, unexpired) tokens — for status/diagnostics."""
        self._gc()
        return len(self._grants)


def bootstrap_command(core_base_url: str, raw_token: str, *, image: str, serve_image: bool) -> str:
    """The one-line command the operator runs on the target to self-enrol (ADR-026 §Mode B).

    When ``serve_image`` is set (core has an image archive), the bootstrap loads the agent image
    **only if it is not already present** (``docker image inspect`` guard — idempotent, no needless
    multi-hundred-MB transfer), then fetches the bundle, unpacks it and starts the agent. The
    image fetch (non-secret) uses the token without consuming it; the bundle fetch (secret cert)
    consumes it — so the image step must precede the bundle step.
    """
    base = core_base_url.rstrip("/")
    # The token rides an Authorization header, not the URL, so it does not land in access logs /
    # shell history (round-1 F-2). It is held in a shell variable for the same reason.
    auth = '-H "Authorization: Bearer $T"'
    image_step = (
        f'docker image inspect "{image}" >/dev/null 2>&1 || '
        f'curl -fsSL {auth} "{base}/api/v1/deployment/enroll/image" | sudo docker load; '
        if serve_image
        else ""
    )
    # Hardening (round-2 P1/P3): pipefail so a broken `curl | docker load` aborts; an unpredictable
    # mktemp tarball path (no /tmp symlink race); and `tar --no-same-owner --no-overwrite-dir` so a
    # substituted/hostile archive cannot chown to root or clobber existing dirs on extract. NOTE:
    # integrity still depends on the transport — front core_base_url with HTTPS (threat-model T-2).
    return (
        f'set -eo pipefail; T="{raw_token}"; DIR=${{FATHOM_DIR:-/opt/fathom-agent}}; '
        'TGZ=$(mktemp); sudo mkdir -p "$DIR"; '
        f"{image_step}"
        f'curl -fsSL {auth} "{base}/api/v1/deployment/enroll/bundle" -o "$TGZ"; '
        'sudo tar --no-same-owner --no-overwrite-dir -xzf "$TGZ" -C "$DIR"; rm -f "$TGZ"; '
        'cd "$DIR" && sudo docker compose up -d agent && echo "fathom agent enrolled"'
    )


def windows_powershell_bootstrap(core_base_url: str, raw_token: str, *, install_dir: str) -> str:
    """The one-line **PowerShell** command an operator runs (elevated) to self-enrol on Windows.

    Native W1 install (no Docker): force TLS 1.2 (PowerShell 5.1 on Server 2016 does not default to
    it), download the bundle **zip** to a unique temp file with the token on an ``Authorization``
    header (never the URL — keeps it out of logs/history, mirroring the bash path's round-1 F-2),
    ``Expand-Archive`` into the install dir, then run the bundled installer which registers the
    daily Scheduled Task. ``install_dir`` is operator-controlled config (a validated Windows path);
    it is single-quoted into the PowerShell literal and is not attacker-supplied.

    The install dir is **locked to SYSTEM + Administrators before the bundle lands** (Win-review
    finding): ``%PROGRAMDATA%`` lets standard users create subdirectories, so without this a
    non-admin could pre-create the dir (retaining write access) and later have the SYSTEM scheduled
    task run an attacker-replaced ``run-scan.ps1`` — a local privilege escalation — or read the
    agent's private key at rest. So the bootstrap (a) refuses a pre-existing dir not owned by
    SYSTEM/Administrators (squat detection, fail-closed), and (b) takes ownership + strips inherited
    ACEs + grants only SYSTEM/Administrators, both before extraction and again after, so the private
    key and scripts are never readable/writable by non-admins. This is the Windows analogue of the
    Linux path's ``chmod 0600`` + ``tar --no-overwrite-dir``.

    NOTE: as with the bash bootstrap, integrity depends on the transport — front ``core_base_url``
    with HTTPS (threat-model T-2); the bundle carries the agent's private key. The enroll route logs
    a warning when ``core_base_url`` is plain http.
    """
    base = core_base_url.rstrip("/")
    dir_lit = "'" + install_dir.replace("'", "''") + "'"
    # SYSTEM = S-1-5-18, Administrators = S-1-5-32-544 (SID literals → locale-independent).
    lock = (
        "icacls $D /inheritance:r /grant:r "
        "'*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q | Out-Null; "
    )
    # token_urlsafe → [A-Za-z0-9_-]; safe inside a double-quoted PowerShell string (no $/`/" in it).
    return (
        "$ErrorActionPreference='Stop'; "
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; "
        f'$T="{raw_token}"; $D={dir_lit}; '
        # Fail closed on a pre-existing install dir not owned by SYSTEM/Administrators (squatting).
        "if (Test-Path $D) { "
        "$o=(Get-Acl $D).GetOwner([System.Security.Principal.SecurityIdentifier]).Value; "
        "if ($o -ne 'S-1-5-18' -and $o -ne 'S-1-5-32-544') "
        '{ throw "refusing: $D exists with owner $o (not SYSTEM/Administrators)" } }; '
        "New-Item -ItemType Directory -Force -Path $D | Out-Null; "
        # Take ownership + lock to SYSTEM/Administrators BEFORE the bundle (with the key) lands.
        "icacls $D /setowner '*S-1-5-32-544' /T /C /Q | Out-Null; "
        f"{lock}"
        "$Z=Join-Path $env:TEMP ('fathomline-'+[guid]::NewGuid().ToString()+'.zip'); "
        "Invoke-WebRequest -UseBasicParsing -Headers @{Authorization=('Bearer '+$T)} "
        f"-Uri '{base}/api/v1/deployment/enroll/bundle' -OutFile $Z; "
        "Expand-Archive -Path $Z -DestinationPath $D -Force; Remove-Item $Z; "
        # Re-assert the lock so the freshly extracted files carry only the SYSTEM/Admins DACL.
        f"{lock}"
        "& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $D 'install-agent.ps1'); "
        "Write-Host 'fathomline agent enrolled'"
    )
