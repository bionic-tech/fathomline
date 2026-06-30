"""Agent host-facts probe (ADR-037) — best-effort hardware detection for the suitability engine.

Reports CPU cores + model, total RAM, GPU name + VRAM, and CPU architecture so the server can rate
which AI options fit this host. Everything is best-effort and fail-soft: any probe that errors or is
unavailable simply yields ``None`` for that field — this never raises and never blocks a scan. The
result is attached to the ingest ``HostFrame.facts`` (the server persists it onto ``host.facts``).

Pure stdlib (``/proc`` on Linux + an optional ``nvidia-smi`` shell-out); no new dependency.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from fathom.logging import get_logger

_log = get_logger("fathom.agent.host_facts")


def _cpu_cores() -> int | None:
    try:
        return os.cpu_count()
    except Exception:
        return None


def _cpu_model() -> str | None:
    # Linux: the first "model name" line of /proc/cpuinfo; otherwise platform.processor().
    try:
        with Path("/proc/cpuinfo").open(encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()[:255]
    except OSError:
        pass
    proc = platform.processor()
    return proc[:255] if proc else None


def _ram_bytes() -> int | None:
    # Linux: MemTotal (kB) from /proc/meminfo; otherwise sysconf if the platform exposes it.
    try:
        with Path("/proc/meminfo").open(encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if pages > 0 and page_size > 0:
            return pages * page_size
    except (ValueError, OSError, AttributeError):
        pass
    return None


def _gpu() -> tuple[str | None, int | None]:
    # Best-effort NVIDIA probe via nvidia-smi. Absent tool / non-NVIDIA / any error → (None, None).
    exe = shutil.which("nvidia-smi")
    if exe is None:
        return None, None
    try:
        out = subprocess.run(  # noqa: S603 — fixed argv, no shell, bounded timeout
            [exe, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    if out.returncode != 0 or not out.stdout.strip():
        return None, None
    # First GPU line: "NVIDIA GeForce RTX 4060, 8192"  (name, MiB).
    first = out.stdout.strip().splitlines()[0]
    parts = [p.strip() for p in first.split(",")]
    name = parts[0][:255] if parts and parts[0] else None
    vram: int | None = None
    if len(parts) >= 2:
        try:
            vram = int(parts[1]) * 1024 * 1024  # MiB → bytes
        except ValueError:
            vram = None
    return name, vram


def collect() -> dict[str, Any]:
    """Probe host hardware; return a dict matching ``HostFactsFrame`` (any field may be None)."""
    gpu_name, gpu_vram = _gpu()
    facts: dict[str, Any] = {
        "cpu_cores": _cpu_cores(),
        "cpu_model": _cpu_model(),
        "ram_bytes": _ram_bytes(),
        "gpu_name": gpu_name,
        "gpu_vram_bytes": gpu_vram,
        "arch": platform.machine() or None,
    }
    _log.debug("probed host facts", extra={"facts": facts})
    return facts
