"""Windows path-safety primitives (ADR-027 phase W1 §paths; AR-0012 discipline).

The Windows counterpart of :mod:`fathom.security.paths`: every path the future Windows
agent accepts from config or re-validates from the wire passes through here. The rules are
fail-closed and deliberately stricter than Win32 itself, because Win32's own normalisation
(silently stripping trailing dots/spaces, DOS device aliases like ``NUL.txt``, alternate
data streams) is exactly what an attacker uses to alias two spellings of one file.

Pure, side-effect-free string operations on ``ntpath``/``PureWindowsPath`` — they never
touch a filesystem, so they run (and are tested) on every platform. The Windows walker and
service that consume them arrive with the rest of phase W1.

Rules enforced:
- absolute only: drive-rooted (``C:\\data``) or UNC (``\\\\server\\share\\…``); the
  ``\\\\?\\`` / ``\\\\?\\UNC\\`` long-path prefixes are accepted and canonicalised away.
- rejected outright: drive-relative (``C:data``), rootless (``\\data``), relative paths,
  NUL/control characters, Win32-forbidden name characters, alternate data streams
  (``file:stream``), reserved device names (``CON``, ``NUL``, ``COM1``…, with or without an
  extension), and components ending in a dot or space (Win32 strips them — aliasing).
- joins prove containment **case-insensitively** (NTFS default), unlike the POSIX rules.
"""

from __future__ import annotations

import ntpath
import re
from pathlib import PureWindowsPath

from fathom.security.paths import PathSafetyError

__all__ = [
    "is_reserved_component",
    "safe_windows_path_join",
    "strip_long_path_prefix",
    "validate_windows_config_path",
]

_LONG_PREFIX = "\\\\?\\"
_LONG_UNC_PREFIX = "\\\\?\\UNC\\"
# CON/PRN/AUX/NUL/COM1-9/LPT1-9 are devices in EVERY directory, even with an extension
# ("NUL.txt" opens the NUL device). Superscript COM/LPT digits exist too but are not valid
# in our strict charset anyway.
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)", re.IGNORECASE)
# Win32-forbidden filename characters (``\\`` and ``/`` are separators; ``:`` is handled
# separately so the drive specifier survives).
_FORBIDDEN_CHARS = frozenset('<>"|?*')


def strip_long_path_prefix(text: str) -> str:
    """Return ``text`` with a ``\\\\?\\`` or ``\\\\?\\UNC\\`` prefix canonicalised away."""
    if text.startswith(_LONG_UNC_PREFIX):
        return "\\\\" + text[len(_LONG_UNC_PREFIX) :]
    if text.startswith(_LONG_PREFIX):
        return text[len(_LONG_PREFIX) :]
    return text


def is_reserved_component(name: str) -> bool:
    """True if ``name`` is a DOS reserved device name (with or without an extension)."""
    return bool(_RESERVED.match(name))


def _check_component(comp: str, *, original: str) -> None:
    """Fail closed on any component Win32 would alias, reserve, or refuse."""
    if any(ch in _FORBIDDEN_CHARS for ch in comp) or any(ord(ch) < 32 for ch in comp):
        raise PathSafetyError(f"forbidden character in path component {comp!r}: {original!r}")
    if ":" in comp:
        # An alternate data stream ("report.txt:hidden") — a second addressable byte stream
        # behind one catalogue entry. Never traversed, never accepted.
        raise PathSafetyError(f"alternate data stream not allowed: {original!r}")
    if is_reserved_component(comp):
        raise PathSafetyError(f"reserved device name in path: {comp!r}")
    if comp != comp.rstrip(" ."):
        # Win32 silently strips trailing dots/spaces, making "data." alias "data".
        raise PathSafetyError(f"path component ends with dot/space: {comp!r}")


def _normalise(text: str, *, original: str) -> tuple[str, str, list[str]]:
    """Normalise to ``(drive, norm, components)``; fail closed on malformed input."""
    if not text:
        raise PathSafetyError("path is empty")
    if "\x00" in text:
        raise PathSafetyError("path contains a NUL byte")
    stripped = strip_long_path_prefix(text)
    norm = ntpath.normpath(stripped)
    drive, rest = ntpath.splitdrive(norm)
    if not drive or not ntpath.isabs(norm):
        # Catches relative paths, drive-relative "C:data", and rootless "\\data" alike.
        raise PathSafetyError(
            f"path must be drive-rooted (C:\\…) or UNC (\\\\server\\share\\…): {original!r}"
        )
    components = [c for c in rest.split("\\") if c]
    for comp in components:
        _check_component(comp, original=original)
    return drive, norm, components


def validate_windows_config_path(value: str) -> PureWindowsPath:
    """Validate and canonicalise a Windows configuration path (pure; no filesystem access).

    Accepts drive-rooted and UNC absolutes, with or without the ``\\\\?\\`` long-path
    prefix; forward slashes are tolerated and normalised. Existence/type checks are the
    Windows agent runtime's job — this validates *intent*, exactly like the POSIX
    :func:`~fathom.security.paths.validate_config_path` does.

    Raises:
        PathSafetyError: On anything relative, drive-relative, rootless, stream-qualified,
            reserved, control-charactered, or Win32-aliasable.
    """
    _, norm, _ = _normalise(value, original=value)
    return PureWindowsPath(norm)


def safe_windows_path_join(base: str, candidate: str) -> PureWindowsPath:
    """Join ``candidate`` under ``base`` and prove containment, case-insensitively.

    The candidate must be relative — an absolute, drive-qualified, or UNC candidate is an
    override attempt and fails closed, as does any ``..`` escape. Containment is proven on
    casefolded components because NTFS is case-insensitive by default: ``C:\\Data`` and
    ``c:\\DATA`` are the same directory and must be treated as such.

    Raises:
        PathSafetyError: If ``base`` is not a valid absolute Windows path, or the candidate
            is absolute/drive-qualified, or the normalised join escapes the base.
    """
    _, base_norm, base_comps = _normalise(base, original=base)

    if not candidate:
        raise PathSafetyError("candidate path is empty")
    if "\x00" in candidate:
        raise PathSafetyError("path contains a NUL byte")
    cand = strip_long_path_prefix(candidate).replace("/", "\\")
    if ntpath.splitdrive(cand)[0] or cand.startswith("\\"):
        raise PathSafetyError(f"candidate must be relative: {candidate!r}")

    _, joined_norm, joined_comps = _normalise(ntpath.join(base_norm, cand), original=candidate)

    base_key = [c.casefold() for c in base_comps]
    joined_key = [c.casefold() for c in joined_comps]
    if joined_key[: len(base_key)] != base_key:
        raise PathSafetyError(f"path escapes base: {candidate!r} not within {base!r}")
    return PureWindowsPath(joined_norm)
