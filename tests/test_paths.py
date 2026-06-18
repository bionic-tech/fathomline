"""Tests for the path-safety primitives (AR-0012)."""

from __future__ import annotations

import pytest

from fathom.security.paths import PathSafetyError, safe_path_join, validate_config_path


def test_validate_rejects_relative() -> None:
    with pytest.raises(PathSafetyError):
        validate_config_path("etc/passwd")


def test_validate_rejects_empty() -> None:
    with pytest.raises(PathSafetyError):
        validate_config_path("")


def test_validate_rejects_nul() -> None:
    with pytest.raises(PathSafetyError):
        validate_config_path("/etc/pa\x00sswd")


def test_validate_normalises() -> None:
    assert str(validate_config_path("/var/../etc/passwd")) == "/etc/passwd"


def test_validate_must_exist(tmp_path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(PathSafetyError):
        validate_config_path(str(missing), must_exist=True)
    real = tmp_path / "here"
    real.write_text("x")
    assert validate_config_path(str(real), must_be_file=True) == real


def test_safe_join_contains() -> None:
    expected = validate_config_path("/srv/data/media/movies")
    assert safe_path_join("/srv/data", "media/movies") == expected


@pytest.mark.parametrize("escape", ["../etc/passwd", "../../root", "/etc/passwd"])
def test_safe_join_rejects_escape(escape: str) -> None:
    with pytest.raises(PathSafetyError):
        safe_path_join("/srv/data", escape)


def test_safe_join_equal_base_ok() -> None:
    assert safe_path_join("/srv/data", ".") == validate_config_path("/srv/data")
