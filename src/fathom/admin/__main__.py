"""``python -m fathom.admin`` — operator commands (ADR-010).

``create-admin`` seeds the initial local admin from a one-time env/secret credential. No
secrets in argv: the password is read from the environment (``FATHOM_BOOTSTRAP_ADMIN_*``),
not the command line.

``remediation-keygen <out_dir>`` generates the orchestrator's Ed25519 signing keypair for the
dispatch channel (ADR-025): the private PEM (→ core's secret backend, by reference) and the
public PEM (→ each agent, pinned). It only *generates* material; it provisions nothing and
enables nothing — that is the separate, deliberately-authorised enablement step.
"""

from __future__ import annotations

import asyncio
import os
import sys

from fathom.admin.bootstrap import bootstrap_admin, read_bootstrap_credential
from fathom.core.db import session_scope
from fathom.core.remediation.keygen import (
    DEFAULT_KEY_ID,
    generate_orchestrator_keypair,
    write_keypair,
)
from fathom.logging import configure_logging, get_logger

_log = get_logger("fathom.admin")


async def _create_admin() -> int:
    username, password = read_bootstrap_credential()
    async with session_scope() as session:
        result = await bootstrap_admin(session, username=username, password=password)
    if result.created:
        _log.info("bootstrapped local admin %r (global scope)", result.username)
    else:
        _log.info("local admin %r already present — no change", result.username)
    return 0


def _remediation_keygen(args: list[str]) -> int:
    """Generate the orchestrator signing keypair into ``args[0]`` (ADR-025 key distribution)."""
    if not args:
        _log.error("usage: python -m fathom.admin remediation-keygen <out_dir>")
        return 2
    out_dir = args[0]
    key_id = os.environ.get("FATHOM_REMEDIATION_SIGNING_KEY_ID", DEFAULT_KEY_ID)
    material = generate_orchestrator_keypair(key_id=key_id)
    private_path, public_path = write_keypair(material, out_dir=out_dir)
    # Log the *paths* and guidance only — never the key material (count-only/secret-safe logging).
    _log.info(
        "generated orchestrator signing keypair",
        extra={
            "key_id": key_id,
            "private_path": str(private_path),
            "public_path": str(public_path),
        },
    )
    _log.info(
        "next steps (do NOT commit the private key): load %s into core's secret backend and set "
        "FATHOM_REMEDIATION_SIGNING_KEY_REF to its reference; distribute %s to each agent's secret "
        "backend and set orchestrator_pubkey_ref + orchestrator_key_id=%r. Provisioning + enabling "
        "the write path is a separate, deliberately-authorised step.",
        private_path,
        public_path,
        key_id,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """Dispatch an admin subcommand."""
    configure_logging()
    args = argv if argv is not None else sys.argv[1:]
    if args and args[0] == "create-admin":
        return asyncio.run(_create_admin())
    if args and args[0] == "remediation-keygen":
        return _remediation_keygen(args[1:])
    _log.error("usage: python -m fathom.admin {create-admin | remediation-keygen <out_dir>}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
