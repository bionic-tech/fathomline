"""Server-side path risk classification (the authority behind the UI's risk labels).

Mirrors ``src/fathom/web/src/lib/riskClass.ts`` so the *server* — not just the browser — decides
whether a destructive plan touches operating-system or service-state files. The remediation
acknowledgement gate (ADR-024-adjacent; the "danger zone") uses this to record which risk classes a
delete/move touches and to flag a high-risk act, so a client cannot relabel a path to dodge the
caution. Four classes, by descending danger: ``os`` > ``services`` > ``config`` > ``user``.
"""

from __future__ import annotations

# Unambiguous OS markers — matched as a whole path component ANYWHERE (these almost never occur in
# user data, so even .../backup/etc/passwd reads as OS).
_STRONG_OS = frozenset(
    {
        "etc",
        "boot",
        "sys",
        "proc",
        "windows",
        "system32",
        "winsxs",
        "programdata",
        "program files",
        "program files (x86)",
    }
)

# Ambiguous OS dirs — OS only when they are the path ROOT (first real component). "lib"/"var"/etc.
# legitimately appear inside user and service trees (e.g. /var/lib/docker), so matching them
# anywhere over-flags; the services check runs first so /var/lib/docker stays services.
_ROOT_OS = frozenset({"usr", "bin", "sbin", "lib", "lib64", "dev", "run", "root", "var"})

# Service / application-state directories. A component equal to one of these, or containing
# "docker", marks the subtree as services (after config files are split off).
_SERVICE_DIRS = frozenset(
    {
        "overlay2",
        "containers",
        "containerd",
        "volumes",
        "pgdata",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "mongodb",
        "mongo",
        "redis",
        "valkey",
        "etcd",
        "appdata",
        ".config",
    }
)

# Risk class labels (kept in sync with riskClass.ts).
OS = "os"
SERVICES = "services"
CONFIG = "config"
USER = "user"

# The classes that warrant extra caution on a destructive action (the "high-risk" set).
HIGH_RISK = frozenset({OS, SERVICES})


def _is_config_file(name: str) -> bool:
    n = name.lower()
    if n == ".env" or n.endswith(".env"):
        return True
    if n.startswith("docker-compose") or n.startswith("compose."):
        return True
    if n == "dockerfile" or n.startswith("dockerfile."):
        return True
    return (
        n.endswith(".conf")
        or n.endswith(".cfg")
        or n.endswith(".ini")
        or n.endswith(".service")
        or n == "nginx.conf"
    )


def classify_path(path: str, name: str | None = None) -> str:
    """Classify a path into a risk class from its components + basename (heuristic, UI-only signal).

    Returns one of ``os`` | ``services`` | ``config`` | ``user``. Precedence: unambiguous OS markers
    win first; then a config/compose/env FILE (checked before the docker heuristic so a compose file
    is ``config``, not falsely ``services``); then service dirs; then root-only OS dirs; then user.
    """
    comps = [c.strip().lower() for c in path.split("/") if c.strip()]
    base = (name or (comps[-1] if comps else "")).lower()
    # Strip a leading "scan" mount alias so /scan/etc/... still reads as OS (agents mount at /scan).
    real = comps[1:] if comps and comps[0] == "scan" else comps

    if any(c in _STRONG_OS for c in real):
        return OS
    if _is_config_file(base):
        return CONFIG
    if any(c in _SERVICE_DIRS or "docker" in c for c in real):
        return SERVICES
    if real and real[0] in _ROOT_OS:
        return OS
    return USER


def classify_paths(paths: list[str]) -> dict[str, int]:
    """Count how many of ``paths`` fall into each risk class (for the acknowledgement audit)."""
    counts: dict[str, int] = {OS: 0, SERVICES: 0, CONFIG: 0, USER: 0}
    for p in paths:
        counts[classify_path(p)] += 1
    return counts
