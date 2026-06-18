"""Orchestrator signing-key generation + distribution tooling (ADR-025 §4, ADR-010).

The dispatch channel's trust anchor is an **Ed25519 keypair**: the orchestrator (core) signs every
job with the *private* key; each agent pins the matching *public* key and rejects anything else.
This module generates that keypair and writes the two halves to files so an operator can place
them, **by reference**, into the respective secret backends:

* the **private** PEM → core's secret backend; ``remediation_signing_key_ref`` names it. It must
  never be committed, never land in ``.env`` or an image — only the *reference* is configured
  (ADR-010). The file is written ``0600``.
* the **public** PEM (+ ``key_id``) → each agent's secret backend; ``orchestrator_pubkey_ref``
  names it and ``orchestrator_key_id`` pins it. The public key is not secret, but its ``key_id``
  is the rotation handle: a new key is a new ``key_id`` + redistribution.

This tooling only *generates* material; it never provisions a host or enables the write path — that
is the deliberate, separately-authorised enablement step (ADR-025 §5/step 7).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_KEY_ID = "orchestrator-v1"
DEFAULT_PRIVATE_NAME = "orchestrator_private.pem"
DEFAULT_PUBLIC_NAME = "orchestrator_public.pem"


@dataclass(frozen=True, slots=True)
class OrchestratorKeyMaterial:
    """A generated orchestrator keypair: the private PEM (core) + public PEM (agents) + key id."""

    key_id: str
    private_pem: str  # PKCS8 PEM — into core's secret backend, by reference (never committed)
    public_pem: str  # SubjectPublicKeyInfo PEM — distributed to agents, pinned by key_id


def generate_orchestrator_keypair(*, key_id: str = DEFAULT_KEY_ID) -> OrchestratorKeyMaterial:
    """Generate a fresh Ed25519 orchestrator keypair (owner-recommended primitive, ADR-010 §1)."""
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return OrchestratorKeyMaterial(key_id=key_id, private_pem=private_pem, public_pem=public_pem)


def write_keypair(
    material: OrchestratorKeyMaterial,
    *,
    out_dir: str | Path,
    private_name: str = DEFAULT_PRIVATE_NAME,
    public_name: str = DEFAULT_PUBLIC_NAME,
) -> tuple[Path, Path]:
    """Write the keypair to ``out_dir`` (private ``0600``); return ``(private_path, public_path)``.

    The private key is written with owner-only permissions so it is not world-readable on the
    generating host even before it is moved into the secret backend. The caller is responsible for
    keeping ``out_dir`` off version control and the image.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    private_path = out / private_name
    public_path = out / public_name
    # Create the private file with 0600 from the start (no world-readable window before chmod).
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, material.private_pem.encode("utf-8"))
    finally:
        os.close(fd)
    private_path.chmod(0o600)  # idempotent if it pre-existed with looser perms
    public_path.write_text(material.public_pem, encoding="utf-8")
    return private_path, public_path
