"""Orchestrator key generation + distribution tests (ADR-025 §4).

The generated keypair must be a *working* trust anchor end-to-end: the private half loads as a
core signer and the public half, distributed to an agent, verifies exactly its signatures. The
private file must be written with owner-only permissions, and the admin CLI must surface it
without leaking the key material.
"""

from __future__ import annotations

import stat
from pathlib import Path

from fathom.agent.actor.listen import build_verifier
from fathom.api.remediation_runtime import load_orchestrator_signer
from fathom.core.remediation.keygen import (
    generate_orchestrator_keypair,
    write_keypair,
)
from fathom.core.remediation.signing import sign_job
from fathom.core.settings import Settings


def _job():  # local minimal ActionJob for a round-trip signature check
    from datetime import UTC, datetime, timedelta

    from fathom.core.remediation.job import ActionJob
    from fathom.core.remediation.plan import PlanAction, PlanItem

    now = datetime.now(tz=UTC)
    return ActionJob(
        plan_id="p",
        mode="execute",
        nonce="0123456789abcdef0123",
        issued_at=now,
        expires_at=now + timedelta(seconds=300),
        host_id="nas-1",
        keeper_path="/v/k",
        items=[
            PlanItem(
                entry_id="d",
                path="/v/d",
                prior_inode=1,
                prior_size=1,
                prior_hash="h",
                action=PlanAction.QUARANTINE,
            )
        ],
    )


def test_generated_keypair_is_a_working_trust_anchor(tmp_path: Path) -> None:
    material = generate_orchestrator_keypair(key_id="orchestrator-v1")
    private_path, public_path = write_keypair(material, out_dir=tmp_path)

    # Core loads the PRIVATE half by reference (via the secret backend) and signs a job...
    settings = Settings(
        remediation_enabled=True,
        remediation_signing_key_ref="orch_priv",
        remediation_signing_key_id="orchestrator-v1",
    )
    signer = load_orchestrator_signer(
        settings, secret_provider=lambda _ref: private_path.read_text()
    )
    assert signer is not None
    signed = sign_job(_job(), signer)

    # ...and the agent, pinning the PUBLIC half, verifies exactly that signature.
    verifier = build_verifier(public_path.read_text(), key_id="orchestrator-v1")
    assert verifier.verify_signature(signed) is True


def test_private_key_written_owner_only(tmp_path: Path) -> None:
    material = generate_orchestrator_keypair()
    private_path, public_path = write_keypair(material, out_dir=tmp_path)
    mode = stat.S_IMODE(private_path.stat().st_mode)
    assert mode == 0o600, f"private key must be 0600, got {oct(mode)}"
    assert "PRIVATE KEY" in private_path.read_text()
    assert "PUBLIC KEY" in public_path.read_text()


def test_custom_key_id_is_carried() -> None:
    material = generate_orchestrator_keypair(key_id="orchestrator-v2")
    assert material.key_id == "orchestrator-v2"


def test_admin_cli_keygen_writes_files(tmp_path: Path) -> None:
    from fathom.admin.__main__ import main

    out = tmp_path / "keys"
    rc = main(["remediation-keygen", str(out)])
    assert rc == 0
    assert (out / "orchestrator_private.pem").exists()
    assert (out / "orchestrator_public.pem").exists()
    # The generated pair verifies end-to-end.
    settings = Settings(
        remediation_enabled=True,
        remediation_signing_key_ref="r",
        remediation_signing_key_id="orchestrator-v1",
    )
    signer = load_orchestrator_signer(
        settings, secret_provider=lambda _r: (out / "orchestrator_private.pem").read_text()
    )
    assert signer is not None
    signed = sign_job(_job(), signer)
    verifier = build_verifier(
        (out / "orchestrator_public.pem").read_text(), key_id="orchestrator-v1"
    )
    assert verifier.verify_signature(signed) is True


def test_admin_cli_keygen_requires_out_dir() -> None:
    from fathom.admin.__main__ import main

    assert main(["remediation-keygen"]) == 2


def test_admin_cli_unknown_command() -> None:
    from fathom.admin.__main__ import main

    assert main(["frobnicate"]) == 2
