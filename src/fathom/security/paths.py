"""Path-safety primitives (AR-0012, ADD 01 §Security).

Every path that crosses a trust boundary — agent config, a scan target, an
agent-supplied path re-validated server-side — passes through here. The rules are
deliberately strict and fail-closed: absolute, normalised, no NUL bytes, and (for joins)
provably contained within an allowed base so ``../`` traversal cannot escape.

These are pure, side-effect-free string/path operations: they do **not** touch the
filesystem unless an existence check is explicitly requested. TOCTOU-resistant
``openat``/``O_NOFOLLOW`` enforcement on the *write* path is a separate, later concern
(ADD 02 §Mode 3) — this module is the first, cheap line of defence.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath


class PathSafetyError(ValueError):
    """Raised when a path fails a safety invariant."""


def validate_config_path(
    value: str | os.PathLike[str],
    *,
    must_exist: bool = False,
    must_be_dir: bool = False,
    must_be_file: bool = False,
) -> Path:
    """Validate and normalise a configuration path, returning a resolved ``Path``.

    Args:
        value: The candidate path.
        must_exist: Require the path to exist on disk.
        must_be_dir: Require it to be a directory (implies ``must_exist``).
        must_be_file: Require it to be a regular file (implies ``must_exist``).

    Returns:
        The absolute, normalised path.

    Raises:
        PathSafetyError: If the path is empty, relative, contains a NUL byte, or fails a
            requested existence/type check.
    """
    text = os.fspath(value)
    if not text:
        raise PathSafetyError("path is empty")
    if "\x00" in text:
        raise PathSafetyError("path contains a NUL byte")

    path = Path(text)
    if not path.is_absolute():
        raise PathSafetyError(f"path must be absolute: {text!r}")

    # Normalise without resolving symlinks (we validate config intent, not live FS state).
    normalised = Path(os.path.normpath(text))

    if must_be_dir or must_be_file:
        must_exist = True
    if must_exist and not normalised.exists():
        raise PathSafetyError(f"path does not exist: {normalised}")
    if must_be_dir and not normalised.is_dir():
        raise PathSafetyError(f"path is not a directory: {normalised}")
    if must_be_file and not normalised.is_file():
        raise PathSafetyError(f"path is not a regular file: {normalised}")
    return normalised


def safe_path_join(base: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> Path:
    """Join ``candidate`` under ``base`` and prove the result stays within ``base``.

    Defeats ``../`` traversal and absolute-path override: the normalised join must remain
    a descendant of (or equal to) the normalised base, or the call fails closed.

    Raises:
        PathSafetyError: If ``base`` is not absolute, or the join escapes it.
    """
    base_text = os.fspath(base)
    cand_text = os.fspath(candidate)
    if "\x00" in base_text or "\x00" in cand_text:
        raise PathSafetyError("path contains a NUL byte")

    base_norm = PurePosixPath(os.path.normpath(base_text))
    if not base_norm.is_absolute():
        raise PathSafetyError(f"base must be absolute: {base_text!r}")

    joined = PurePosixPath(os.path.normpath(str(base_norm / cand_text)))
    if joined != base_norm and base_norm not in joined.parents:
        raise PathSafetyError(f"path escapes base: {cand_text!r} not within {base_text!r}")
    return Path(joined)
