"""Export the OpenAPI spec as a committed, drift-checked artifact (the published API reference).

FastAPI generates the spec from the routers + Pydantic models; this module pins a **deterministic**
serialization (sorted keys, fixed indent, trailing newline) so the committed
``docs/api/openapi.json`` is byte-stable and a test can fail on drift — the published reference can
never silently fall out of sync with the code. Building the spec only introspects routes/models;
it opens no database or network (the app's lifespan, which would, is never entered).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Repo-relative location of the committed spec (ships in the public snapshot under docs/api/).
SPEC_RELPATH = "docs/api/openapi.json"


def build_openapi_spec() -> dict[str, Any]:
    """Build the OpenAPI document from the app factory (no DB/network — pure introspection)."""
    from fathom.api.app import create_app
    from fathom.core.settings import Settings

    app = create_app(Settings())
    return app.openapi()


def dump_spec(spec: dict[str, Any]) -> str:
    """Serialize ``spec`` deterministically: sorted keys, 2-space indent, trailing newline."""
    return json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_spec(repo_root: Path) -> Path:
    """Regenerate ``docs/api/openapi.json`` under ``repo_root`` and return its path."""
    path = repo_root / SPEC_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_spec(build_openapi_spec()), encoding="utf-8")
    return path
