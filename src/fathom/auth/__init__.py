"""Fathom human authentication + RBAC (ADD 13, ADD 03 §2; ADR-009/010/011).

The canonical auth package: core models, the Principal/Capability/Role value objects, the
scope filter, the provider chain (local → forward-auth → OIDC), passwords, sessions and MFA.
FastAPI wiring lives in :mod:`fathom.api.auth_deps`; everything imports from here.

This boundary is **separate** from the agent mTLS ingest path (:mod:`fathom.api.deps`
``FingerprintDep``): human auth deps are never attached to the agent surface (ADD 03 §3,
AR-0012). All access is deny-by-default (ADD 13 §4); scope is server-authoritative and
never derived from client input.
"""

from __future__ import annotations
