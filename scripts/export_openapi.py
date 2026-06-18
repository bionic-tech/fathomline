#!/usr/bin/env python
"""Regenerate the committed OpenAPI spec (docs/api/openapi.json).

Run after any change to a route or request/response model:

    python scripts/export_openapi.py

The CI test ``tests/api/test_openapi.py::test_committed_spec_is_in_sync`` fails if the committed
spec drifts from the code, so the published API reference stays honest.
"""

from __future__ import annotations

from pathlib import Path

from fathom.api.openapi_export import write_spec


def main() -> int:
    path = write_spec(Path(__file__).resolve().parents[1])
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
