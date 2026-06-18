"""Auth-suite fixtures — reuse the API/catalogue fixtures (real ASGI app + temp SQLite)."""

from __future__ import annotations

from tests.api.conftest import api_client, settings

__all__ = ["api_client", "settings"]
