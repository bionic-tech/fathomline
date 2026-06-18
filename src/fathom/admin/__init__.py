"""Operator admin CLI (``python -m fathom.admin``).

Houses out-of-band operational commands that must not be exposed over the API — chiefly the
initial local-admin bootstrap, which reads a one-time credential from the environment / a
Docker secret and never a hardcoded password (ADR-010).
"""

from __future__ import annotations
