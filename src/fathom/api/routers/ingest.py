"""Agent ingest router — the mTLS-authenticated push endpoint (ADD 01, ADD 02)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from fathom.api.deps import FingerprintDep, SessionDep
from fathom.api.schemas import (
    AgentRunReport,
    AgentRunResult,
    FinalizeResult,
    IngestBatch,
    IngestResult,
)
from fathom.core.agent_runs import record_agent_run
from fathom.core.finalize import FinalizeService
from fathom.core.ingest import IngestError, IngestService
from fathom.core.settings import get_settings

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


@router.post("/ingest", response_model=IngestResult, status_code=status.HTTP_200_OK)
async def ingest_batch(
    batch: IngestBatch,
    session: SessionDep,
    fingerprint: FingerprintDep,
) -> IngestResult:
    """Accept a batch of fs_entry deltas from an authenticated agent."""
    service = IngestService(session, max_batch=get_settings().ingest_max_batch)
    try:
        return await service.ingest(batch, cert_fingerprint=fingerprint)
    except IngestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/finalize", response_model=FinalizeResult, status_code=status.HTTP_200_OK)
async def finalize_rollups(
    session: SessionDep,
    fingerprint: FingerprintDep,
) -> FinalizeResult:
    """Recompute subtree rollups (and rebuild dedup groups) after the calling host's drain.

    Recomputes ``subtree_rollup`` for the host's freshly-ingested volumes (ADD 09 §8) and, when a
    full-bit pass has landed content hashes, rebuilds the report-only duplicate groups in the same
    transaction so the ``/duplicates`` view reflects the hashed content (the documented interim for
    the arq ``dedup`` queue, ADD 02 §7.1). Carries the SAME mTLS + ingest-proxy-secret boundary as
    ``/ingest`` (``FingerprintDep``) and is NOT on the human-auth path: the host is the verified
    cert fingerprint, never the body, and finalize only ever recomputes that host's volumes
    (AR-0012). The agent calls this once after its drain; a host with nothing new since its last
    finalize recomputes nothing and a metadata-only deployment rebuilds zero dup groups.
    """
    result = await FinalizeService(session).finalize_host(cert_fingerprint=fingerprint)
    return FinalizeResult(
        host_id=result.host_id,
        volume_ids=result.volume_ids,
        rollup_rows=result.rollup_rows,
        dup_groups=result.dup_groups,
    )


@router.post("/runs", response_model=AgentRunResult, status_code=status.HTTP_200_OK)
async def report_run(
    report: AgentRunReport,
    session: SessionDep,
    fingerprint: FingerprintDep,
) -> AgentRunResult:
    """Record the calling agent's end-of-run outcome (fleet observability).

    Same mTLS + ingest-proxy-secret boundary as ``/ingest`` (``FingerprintDep``): the host is the
    verified cert fingerprint, never the body. The server re-derives the aggregate outcome from the
    reported per-scope rows, so a misreporting agent can only describe its own scopes. Best-effort
    from the agent's side — a 404-equivalent (unknown fingerprint) is reported as a no-op, never an
    error, so run-reporting never destabilises an otherwise-good scan.
    """
    run = await record_agent_run(session, cert_fingerprint=fingerprint, report=report)
    if run is None:
        # Unknown fingerprint: authenticated by the boundary but no host row yet (never ingested).
        return AgentRunResult(run_id=0, host_id=0, outcome="unknown_host")
    return AgentRunResult(run_id=run.id, host_id=run.host_id, outcome=run.outcome)
