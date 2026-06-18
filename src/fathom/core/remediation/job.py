"""Signed action-job primitive (ADR-011 §Guards, STRIDE T-3/S-3; API §1.3 data flow).

A remediation action never reaches the agent executor as a bare plan: the orchestrator wraps
the approved item set in an :class:`ActionJob` — a frozen, ``extra='forbid'`` Pydantic v2
envelope carrying a single-use ``nonce``, an ``issued_at``/``expires_at`` window, the target
``host_id`` scope, and the ``mode`` (``dry_run`` then ``execute``). The job is then signed
(:mod:`fathom.core.remediation.signing`); the actor verifies signature + nonce + expiry +
scope *before* any filesystem access (T-3/S-3, E-1). This module holds only the data shapes
and their **canonical serialization** — the exact, stable byte string both the signer and the
verifier hash over, so a re-ordered or re-encoded job can never validate.

The job is the unit of non-repudiation: it embeds the exact prior-state-bound
:class:`~fathom.core.remediation.plan.PlanItem` rows the executor re-verifies against, so the
signature covers *what will be touched*, not just an opaque plan id.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from fathom.core.remediation.plan import PlanItem

JobMode = Literal["dry_run", "execute"]


class ActionJob(BaseModel):
    """A scoped, time-boxed, single-use unit of remediation work (ADR-011 §Guards).

    ``items`` are the prior-state-bound plan items the actor re-verifies and acts on; the
    signature (computed over :meth:`canonical_bytes`) covers every field including them, so a
    tampered item set fails verification before any filesystem access (T-3).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(min_length=1)
    mode: JobMode
    nonce: str = Field(min_length=16)  # single-use; 128-bit+ CSPRNG hex
    issued_at: datetime
    expires_at: datetime
    host_id: str = Field(min_length=1)  # the one host this job may be dispatched to (scope)
    keeper_path: str = Field(min_length=1)
    items: list[PlanItem] = Field(min_length=1)
    # The operator-approved relocation root for a MOVE (Organize-apply) job (ADR-023). Carried in
    # the signed envelope so the actor re-anchors the move to exactly the root the orchestrator
    # signed; NULL for dedup jobs (quarantine/hardlink/delete). The per-item ``dest_rel`` rides on
    # the signed ``items`` and is covered by the signature via ``canonical_bytes`` below.
    move_root: str | None = None

    def canonical_bytes(self) -> bytes:
        """Return the stable, deterministic byte string the signature is computed over.

        Sorted keys + compact separators + ISO-8601 timestamps make the encoding canonical:
        two semantically equal jobs always serialise identically, and any field change (a
        re-ordered item, a widened expiry, a swapped path) changes these bytes and therefore
        invalidates the signature (T-3). ``item`` order is preserved as significant — the job
        is signed exactly as issued.
        """
        payload: dict[str, object] = {
            "plan_id": self.plan_id,
            "mode": self.mode,
            "nonce": self.nonce,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "host_id": self.host_id,
            "keeper_path": self.keeper_path,
            "move_root": self.move_root,
            "items": [
                {
                    "entry_id": str(item.entry_id),
                    "path": item.path,
                    "prior_inode": item.prior_inode,
                    "prior_size": item.prior_size,
                    "prior_hash": item.prior_hash,
                    "action": item.action.value,
                    # ``dest_rel`` is the destination the executor acts on for a MOVE — signing it
                    # binds the approved target into the non-repudiable envelope (T-3).
                    "dest_rel": item.dest_rel,
                }
                for item in self.items
            ],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SignedJob(BaseModel):
    """An :class:`ActionJob` plus its detached signature (base64) and key id (ADR-010).

    The actor receives this over the agent-initiated outbound channel and must call
    :func:`fathom.core.remediation.signing.verify_job` — never trust ``job`` directly.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    job: ActionJob
    key_id: str = Field(min_length=1)
    algorithm: Literal["ed25519", "hmac-sha256"]
    signature: str = Field(min_length=1)  # base64-encoded
