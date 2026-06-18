"""Read-only directory lister for live browse (ADR-034 Phase 2).

Given a verified :class:`~fathom.core.browse.BrowseRequest`, list exactly ONE directory and return
metadata only — names, types, own size, mtime, and (optionally) a BOUNDED subtree size + file-count
per child dir. It **never opens file contents**, never follows symlinks (no escape/loops),
and is bounded on every axis (entry cap per directory; entry-count + time budget per sizing walk).

The functions here are synchronous ``os`` calls; the browse-serve loop runs them in a thread so the
event loop is never blocked (the same pattern as the scanner's walk).
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from fathom.core.browse import BrowseEntry, BrowseRequest, BrowseResult
from fathom.logging import get_logger

_log = get_logger("fathom.agent.browse")


def _safe_error(exc: OSError) -> str:
    """A sanitised error string for the UI (errno name + message, never a stack/path dump)."""
    name = os.strerror(exc.errno) if exc.errno is not None else exc.__class__.__name__
    return name


def _bounded_subtree(path: str, *, max_entries: int, budget_ms: int) -> tuple[int, int, bool]:
    """Walk ``path`` (no symlink following) accumulating (bytes, file_count) until a cap is hit.

    Returns ``(subtree_size, file_count, truncated)``. ``truncated`` is True if the entry cap or the
    time budget stopped the walk early (so the UI can show "≥ N"). Unreadable subdirs are skipped.
    """
    total_size = 0
    file_count = 0
    seen = 0
    deadline = time.monotonic() + (budget_ms / 1000.0)
    stack = [path]
    while stack:
        if seen >= max_entries or time.monotonic() >= deadline:
            return total_size, file_count, True
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for de in it:
                    seen += 1
                    if seen >= max_entries:
                        return total_size, file_count, True
                    try:
                        if de.is_symlink():
                            continue  # never follow symlinks (no escape, no loops)
                        if de.is_dir(follow_symlinks=False):
                            stack.append(de.path)
                        else:
                            st = de.stat(follow_symlinks=False)
                            total_size += st.st_size
                            file_count += 1
                    except OSError:
                        continue  # unreadable entry — skip, never abort the rollup
        except OSError:
            continue  # unreadable directory — skip
    return total_size, file_count, False


def list_directory(request: BrowseRequest) -> BrowseResult:
    """List one directory per ``request`` (read-only, metadata only). Never raises on FS errors."""
    path = request.path
    try:
        # Refuse to list *through* a symlinked directory target (no escape via a swapped link).
        if Path(path).is_symlink():
            return BrowseResult(request_id=request.request_id, path=path, error="path is a symlink")
        entries: list[BrowseEntry] = []
        truncated = False
        with os.scandir(path) as it:
            for de in it:
                if len(entries) >= request.max_entries:
                    truncated = True
                    break
                try:
                    is_symlink = de.is_symlink()
                    is_dir = de.is_dir(follow_symlinks=False)
                    st = de.stat(follow_symlinks=False)
                except OSError:
                    continue  # entry vanished / unreadable between scandir and stat — skip
                subtree_size: int | None = None
                subtree_count: int | None = None
                subtree_truncated = False
                if request.with_sizes and is_dir and not is_symlink:
                    subtree_size, subtree_count, subtree_truncated = _bounded_subtree(
                        de.path,
                        max_entries=request.size_max_entries,
                        budget_ms=request.size_budget_ms,
                    )
                entries.append(
                    BrowseEntry(
                        name=de.name,
                        path=de.path,
                        is_dir=is_dir,
                        is_symlink=is_symlink,
                        size=st.st_size,
                        mtime=st.st_mtime,
                        subtree_size=subtree_size,
                        subtree_file_count=subtree_count,
                        subtree_truncated=subtree_truncated,
                    )
                )
        # Directories first, then alphabetical — the order a folder picker expects.
        entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
        return BrowseResult(
            request_id=request.request_id, path=path, entries=entries, truncated=truncated
        )
    except OSError as exc:
        _log.info("browse listing failed", extra={"path": path, "error": _safe_error(exc)})
        return BrowseResult(request_id=request.request_id, path=path, error=_safe_error(exc))
