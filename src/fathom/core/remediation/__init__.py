"""Remediation domain — plan modelling and human-selected keepers (ADR-011, ADD 02 §Mode 3).

The highest-risk surface in Fathom. This package holds only the *plan* (pure data) and its
construction; the live-filesystem dry-run verification and the guarded executor live in
``fathom.agent.actor`` under a separate OS user. Fathom never auto-selects what to remove —
``build_plan`` requires an explicit operator-chosen keeper (ADR-011). No execute path is
reachable remotely in v1 (AR-0003); the executor is library code, exercised by its
regression suite and default-disabled (``write_enabled=False``, AR-0006).
"""

from fathom.core.remediation.job import ActionJob, JobMode, SignedJob
from fathom.core.remediation.nonce_store import DbNonceStore, InMemoryNonceStore
from fathom.core.remediation.orchestrator import (
    BlastCapExceededError,
    GroupMember,
    RemediationOrchestrator,
)
from fathom.core.remediation.plan import (
    Member,
    PlanAction,
    PlanItem,
    RemediationPlan,
    build_plan,
)
from fathom.core.remediation.signing import (
    Ed25519CheckpointSigner,
    Ed25519CheckpointVerifier,
    Ed25519Signer,
    Ed25519Verifier,
    HmacCheckpointSigner,
    HmacCheckpointVerifier,
    HmacSigner,
    HmacVerifier,
    JobVerificationError,
    NonceReuseError,
    sign_job,
    verify_job,
)

__all__ = [
    "ActionJob",
    "BlastCapExceededError",
    "DbNonceStore",
    "Ed25519CheckpointSigner",
    "Ed25519CheckpointVerifier",
    "Ed25519Signer",
    "Ed25519Verifier",
    "GroupMember",
    "HmacCheckpointSigner",
    "HmacCheckpointVerifier",
    "HmacSigner",
    "HmacVerifier",
    "InMemoryNonceStore",
    "JobMode",
    "JobVerificationError",
    "Member",
    "NonceReuseError",
    "PlanAction",
    "PlanItem",
    "RemediationOrchestrator",
    "RemediationPlan",
    "SignedJob",
    "build_plan",
    "sign_job",
    "verify_job",
]
