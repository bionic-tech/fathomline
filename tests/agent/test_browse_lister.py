"""Read-only directory lister for live browse (ADR-034 Phase 2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fathom.agent.browse_lister import list_directory
from fathom.core.browse import BrowseRequest


def _req(path: str, **over: object) -> BrowseRequest:
    now = datetime.now(tz=UTC)
    base = {
        "request_id": "br-1",
        "host_id": "nas-1",
        "path": path,
        "nonce": "b" * 32,
        "issued_at": now,
        "expires_at": now + timedelta(seconds=60),
    }
    return BrowseRequest.model_validate({**base, **over})


def _tree(root: Path) -> None:
    (root / "sub").mkdir()
    (root / "sub" / "a.bin").write_bytes(b"\x00" * 100)
    (root / "sub" / "b.bin").write_bytes(b"\x00" * 50)
    (root / "top.txt").write_bytes(b"hello")
    (root / "empty").mkdir()


def test_lists_one_directory_dirs_first_with_metadata(tmp_path: Path) -> None:
    _tree(tmp_path)
    res = list_directory(_req(str(tmp_path)))
    assert res.error is None
    names = [e.name for e in res.entries]
    # directories first (empty, sub), then files (top.txt)
    assert names == ["empty", "sub", "top.txt"]
    sub = next(e for e in res.entries if e.name == "sub")
    assert sub.is_dir and not sub.is_symlink
    # bounded subtree rollup for the child dir: 100 + 50 bytes, 2 files
    assert sub.subtree_size == 150
    assert sub.subtree_file_count == 2
    assert sub.subtree_truncated is False
    top = next(e for e in res.entries if e.name == "top.txt")
    assert not top.is_dir and top.size == 5
    assert top.subtree_size is None  # files have no subtree rollup


def test_with_sizes_false_skips_rollup(tmp_path: Path) -> None:
    _tree(tmp_path)
    res = list_directory(_req(str(tmp_path), with_sizes=False))
    sub = next(e for e in res.entries if e.name == "sub")
    assert sub.subtree_size is None and sub.subtree_file_count is None


def test_does_not_follow_symlinks(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "link").symlink_to(tmp_path / "sub", target_is_directory=True)
    res = list_directory(_req(str(tmp_path)))
    link = next(e for e in res.entries if e.name == "link")
    assert link.is_symlink is True
    # a symlinked dir is reported but NOT sized (never traversed)
    assert link.subtree_size is None


def test_refuses_symlinked_target(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "ln").symlink_to(tmp_path / "real", target_is_directory=True)
    res = list_directory(_req(str(tmp_path / "ln")))
    assert res.error == "path is a symlink"
    assert res.entries == []


def test_missing_path_returns_error_not_raise(tmp_path: Path) -> None:
    res = list_directory(_req(str(tmp_path / "does-not-exist")))
    assert res.error is not None
    assert res.entries == []


def test_max_entries_truncates(tmp_path: Path) -> None:
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_bytes(b"x")
    res = list_directory(_req(str(tmp_path), max_entries=4))
    assert res.truncated is True
    assert len(res.entries) == 4
