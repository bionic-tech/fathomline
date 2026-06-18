"""Content-aware Organize (ADR-021) — propose a tidier tree for a folder; never act on it here.

This package is the *suggestion* half: read a folder's catalogued entries, build per-file digests,
ask the inference provider (ADR-022) for a proposed structure, and — crucially —
**server-authoritatively clamp every proposed target to the approved root** so a prompt-injected
proposal can never escape (the model advises; the server decides). Applying a proposal is the
remediation engine's job (ADR-023), not this package's.
"""

from __future__ import annotations

from fathom.core.organize.service import (
    ApprovedMove,
    MovePlanBuild,
    OrganizePlanError,
    OrganizeProposal,
    OrganizeService,
    ProposedItem,
    clamp_to_root,
)

__all__ = [
    "ApprovedMove",
    "MovePlanBuild",
    "OrganizePlanError",
    "OrganizeProposal",
    "OrganizeService",
    "ProposedItem",
    "clamp_to_root",
]
