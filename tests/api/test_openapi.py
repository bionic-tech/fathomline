"""The published OpenAPI reference: it builds, every operation is documented, and the committed
``docs/api/openapi.json`` never drifts from the code (ROADMAP: published API reference)."""

from __future__ import annotations

from pathlib import Path

from fathom.api.openapi_export import SPEC_RELPATH, build_openapi_spec, dump_spec

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _operations(spec: dict) -> list[tuple[str, str, dict]]:
    methods = {"get", "post", "put", "patch", "delete", "options", "head"}
    return [
        (method.upper(), path, op)
        for path, item in spec["paths"].items()
        for method, op in item.items()
        if method in methods
    ]


def test_spec_builds_with_core_sections() -> None:
    spec = build_openapi_spec()
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"] == "Fathomline API"
    assert spec["paths"], "expected a non-empty paths object"


def test_every_operation_is_documented() -> None:
    # The published reference must explain every endpoint — a summary or (docstring-derived)
    # description on each operation. Adding a route with neither fails here.
    spec = build_openapi_spec()
    undocumented = [
        f"{method} {path}"
        for method, path, op in _operations(spec)
        if not (op.get("summary") or op.get("description"))
    ]
    assert not undocumented, f"operations missing summary/description: {undocumented}"


def test_every_operation_has_a_tag() -> None:
    # Tags drive the navigation grouping in the rendered reference.
    spec = build_openapi_spec()
    untagged = [f"{method} {path}" for method, path, op in _operations(spec) if not op.get("tags")]
    assert not untagged, f"operations missing a tag: {untagged}"


def test_committed_spec_is_in_sync() -> None:
    # Drift gate: the committed artifact must equal a fresh build. If this fails, run
    # `python scripts/export_openapi.py` and commit the result.
    committed = (_REPO_ROOT / SPEC_RELPATH).read_text(encoding="utf-8")
    assert committed == dump_spec(build_openapi_spec()), (
        "docs/api/openapi.json is stale — regenerate with scripts/export_openapi.py"
    )
