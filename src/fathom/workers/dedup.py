"""The 'dedup' background task — build groups after full-bit ingest (ADD 02 §7.1).

ADD 02 §7.1 specifies an arq-on-Valkey ``dedup`` queue that runs *after full-bit ingest*. To
keep this subsystem gate-green and testable without provisioning Valkey (depends_on: arq +
Valkey "if not yet provisioned, DedupService can be invoked synchronously post-ingest as an
interim"), this module ships a transport-agnostic coroutine — :func:`run_dedup` — that does the
real work against a DB session, plus a thin :func:`dedup_task` arq entrypoint shape that calls
it. Wiring it onto an actual arq worker (Redis/Valkey settings) is a deployment concern; the
task body here is the single source of truth either way.

Design choice (documented per owner ruling): the queue is a thin wrapper; all logic lives in
:class:`~fathom.core.dedup_service.DedupService`, so the same code path runs whether dispatched
by arq or invoked inline post-ingest. No new broker dependency is added to the gate.
"""

from __future__ import annotations

from typing import Any

from fathom.core.db import session_scope
from fathom.core.dedup_service import DedupScope, DedupService
from fathom.logging import get_logger

_log = get_logger("fathom.workers.dedup")


async def run_dedup(
    scope: DedupScope | None = None,
    *,
    job_id: str | None = None,
) -> int:
    """Build the report-only dup groups for ``scope`` in a fresh transaction; return group count.

    Runs :class:`DedupService` over the catalogue's stored full hashes and commits. This is the
    body the arq task and any inline post-ingest call share — report-only, opens no file.
    """
    async with session_scope() as session:
        # rebuild() returns the count without holding every group object (bounded memory at
        # estate scale — collecting them OOM-killed the 1 GiB worker).
        count = await DedupService(session).rebuild(scope=scope, job_id=job_id)
        _log.info("dedup task built groups", extra={"groups": count, "job_id": job_id})
        return count


async def dedup_task(
    ctx: dict[str, Any],
    *,
    volume_ids: list[int] | None = None,
    job_id: str | None = None,
) -> int:
    """arq task entrypoint (ADD 02 §7.1): run the dedup build after full-bit ingest.

    ``ctx`` is arq's per-job context (unused here — the task owns its own DB transaction). The
    scope is reconstructed from the dispatched ``volume_ids`` (empty → estate-wide).
    """
    scope = DedupScope(volume_ids=frozenset(volume_ids or ()))
    return await run_dedup(scope, job_id=job_id)
