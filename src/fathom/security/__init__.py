"""Security primitives shared across agent, core, and API.

Stage 1 ships the path-safety helpers (``validate_config_path`` / ``safe_path_join``)
that the design mandates wherever a path is accepted (ADD 01 §Security, AR-0012). The
mTLS, auth, audit-chain, and remediation guards land with their own stages and reviews.
"""

from fathom.security.paths import (
    PathSafetyError,
    safe_path_join,
    validate_config_path,
)

__all__ = ["PathSafetyError", "safe_path_join", "validate_config_path"]
