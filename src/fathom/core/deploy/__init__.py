"""Agent deployment subsystem (ADR-026).

Default-OFF, ``DEPLOY_AGENT``-capability + step-up-MFA gated. Two enrollment modes:

* **push** — core connects out to a target over SSH, mints a CA-signed client cert, transfers the
  agent bundle, and starts the container (:mod:`fathom.core.deploy.engine`).
* **pull** — core issues a single-use, short-TTL enrollment token; the target self-installs by
  redeeming it over the existing mTLS/HTTPS boundary (:mod:`fathom.core.deploy.enrollment`).

All operator credentials are **transient** — held in memory for one deploy, never persisted or
logged (:class:`~fathom.core.deploy.credentials.SshCredential`). The CA signing key is resolved
**by reference** at runtime (ADR-010), never embedded.
"""

from __future__ import annotations


class DeploymentError(RuntimeError):
    """A deployment operation failed (preflight, SSH, cert mint, bundle, or compose)."""
