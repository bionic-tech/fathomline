"""Windows path-safety rules (ADR-027 W1) — pure logic, runs on every platform.

Mirrors tests/test_paths.py for the POSIX rules. These tests are deliberately
adversarial: every Win32 normalisation quirk an attacker can use to alias two spellings
of one path (long-path prefixes, trailing dots, ADS, reserved devices, case) must either
canonicalise to one spelling or fail closed.
"""

from __future__ import annotations

import pytest

from fathom.security.paths import PathSafetyError
from fathom.security.winpaths import (
    is_reserved_component,
    safe_windows_path_join,
    strip_long_path_prefix,
    validate_windows_config_path,
)

# --------------------------------------------------------------------- validate: accepts


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("C:\\Data", "C:\\Data"),
        ("c:/data/sub", "c:\\data\\sub"),  # forward slashes normalise
        ("C:\\Data\\sub\\..\\other", "C:\\Data\\other"),  # dot-dot resolved in-place
        ("C:\\", "C:\\"),  # drive root is a valid scope
        ("\\\\nas-1\\share\\folder", "\\\\nas-1\\share\\folder"),  # UNC
        ("\\\\?\\C:\\Very\\Long", "C:\\Very\\Long"),  # long-path prefix stripped
        ("\\\\?\\UNC\\nas-1\\share\\x", "\\\\nas-1\\share\\x"),  # long UNC form
    ],
)
def test_validate_accepts_and_canonicalises(raw: str, expected: str) -> None:
    assert str(validate_windows_config_path(raw)) == expected


# --------------------------------------------------------------------- validate: rejects


@pytest.mark.parametrize(
    "raw",
    [
        "",  # empty
        "relative\\path",
        "C:data",  # drive-relative: cwd-dependent on Windows
        "\\data",  # rooted but driveless: drive-dependent
        "C:\\data\x00x",  # NUL
        "C:\\da\nta",  # control char
        "C:\\bad<name>\\x",  # forbidden chars
        "C:\\report.txt:hidden",  # alternate data stream
        "C:\\CON\\logs",  # reserved device as a directory
        "C:\\logs\\NUL.txt",  # reserved device aliased via extension
        "C:\\logs\\com7",  # reserved, case-insensitive
        "C:\\data.\\x",  # trailing dot component (Win32 strips → aliasing)
        "C:\\data \\x",  # trailing space component
    ],
)
def test_validate_rejects(raw: str) -> None:
    with pytest.raises(PathSafetyError):
        validate_windows_config_path(raw)


# --------------------------------------------------------------------------------- joins


def test_join_contains_simple_child() -> None:
    assert str(safe_windows_path_join("C:\\Data", "sub\\file.txt")) == "C:\\Data\\sub\\file.txt"


def test_join_equal_to_base_is_allowed() -> None:
    assert str(safe_windows_path_join("C:\\Data", ".")) == "C:\\Data"


def test_join_is_case_insensitive_like_ntfs() -> None:
    # NTFS treats C:\Data and c:\DATA as one directory — containment must agree.
    joined = safe_windows_path_join("C:\\Data", "Sub\\..\\OTHER")
    assert str(joined) == "C:\\Data\\OTHER"


def test_join_unc_base() -> None:
    joined = safe_windows_path_join("\\\\nas-1\\share\\data", "x\\y")
    assert str(joined) == "\\\\nas-1\\share\\data\\x\\y"


@pytest.mark.parametrize(
    "candidate",
    [
        "..\\escape",  # parent escape
        "..",  # escape to drive root
        "a\\..\\..\\b",  # nested escape
        "D:\\absolute",  # absolute override
        "D:relative",  # drive-qualified relative (cwd-on-other-drive trick)
        "\\rooted",  # rooted override onto base's drive
        "\\\\evil\\share",  # UNC override
        "ok\\report.txt:ads",  # stream smuggled into the leaf
        "ok\\NUL",  # reserved device under the base
        "trailing. \\x",  # aliasable component
        "",  # empty
    ],
)
def test_join_rejects(candidate: str) -> None:
    with pytest.raises(PathSafetyError):
        safe_windows_path_join("C:\\Data", candidate)


# ------------------------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    ("name", "reserved"),
    [
        ("CON", True),
        ("con", True),
        ("NUL.txt", True),
        ("COM1", True),
        ("LPT9.log", True),
        ("COM0", False),  # only 1-9 are devices
        ("CONSOLE", False),
        ("data", False),
    ],
)
def test_is_reserved_component(name: str, reserved: bool) -> None:
    assert is_reserved_component(name) is reserved


def test_strip_long_path_prefix_variants() -> None:
    assert strip_long_path_prefix("\\\\?\\C:\\x") == "C:\\x"
    assert strip_long_path_prefix("\\\\?\\UNC\\srv\\sh") == "\\\\srv\\sh"
    assert strip_long_path_prefix("C:\\x") == "C:\\x"
