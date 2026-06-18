"""Remediation orchestrator tests (STRIDE T-2 + audit-before-act + server blast cap).

The named ``test_T2_*`` case: the orchestrator dispatches an EXECUTE job for the non-drifted
subset ONLY — a drifted item returned by the dry-run is dropped from the execute job and never
acted on. Also covers the server-authoritative blast cap and the audit trail.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.agent.actor.planner import VerifyReport
from fathom.core.audit import AuditChain, verify_chain
from fathom.core.remediation.job import SignedJob
from fathom.core.remediation.orchestrator import (
    BlastCapExceededError,
    ExecuteOutcome,
    GroupMember,
    RemediationOrchestrator,
)
from fathom.core.remediation.signing import Ed25519Signer

HOST = "nas-1"


def _signer() -> Ed25519Signer:
    return Ed25519Signer(Ed25519PrivateKey.generate(), key_id="orchestrator-v1")


def _members(n: int) -> list[GroupMember]:
    return [
        GroupMember(
            entry_id=i,
            host_id=1,
            volume_id=1,
            path=f"/v/file{i}.bin",
            inode=1000 + i,
            size=4096,
        )
        for i in range(n)
    ]


def _orch(*, blast_cap: int = 100) -> tuple[RemediationOrchestrator, list[object]]:
    sink: list[object] = []
    orch = RemediationOrchestrator(
        audit=AuditChain(sink=sink.append),
        signer=_signer(),
        blast_cap=blast_cap,
    )
    return orch, sink


def test_build_requires_existing_keeper() -> None:
    orch, _ = _orch()
    with pytest.raises(ValueError, match="not a member"):
        orch.build(
            plan_id="p",
            members=_members(2),
            keep_id=999,
            full_hash="F",
            created_by="mo",
            target_host_id=HOST,
        )


def test_build_rejects_unsafe_path() -> None:
    orch, _ = _orch()
    bad = [GroupMember(entry_id=0, host_id=1, volume_id=1, path="relative/x", inode=1, size=1)]
    bad.append(GroupMember(entry_id=1, host_id=1, volume_id=1, path="/v/ok.bin", inode=2, size=1))
    with pytest.raises(ValueError, match="path safety"):
        orch.build(
            plan_id="p",
            members=bad,
            keep_id=1,
            full_hash="F",
            created_by="mo",
            target_host_id=HOST,
        )


def test_build_audits_intent() -> None:
    orch, sink = _orch()
    plan = orch.build(
        plan_id="p1",
        members=_members(3),
        keep_id=0,
        full_hash="F",
        created_by="mo",
        target_host_id=HOST,
    )
    assert len(plan.items) == 2  # 3 members minus the keeper
    assert verify_chain(sink) is True
    assert any(r.action == "remediation.plan.build" for r in sink)  # type: ignore[attr-defined]


async def test_execute_dispatches_only_non_drifted_subset() -> None:
    # T-2: dry-run flags one item drifted; execute must carry ONLY the clean item.
    orch, _sink = _orch()
    plan = orch.build(
        plan_id="p2",
        members=_members(3),
        keep_id=0,
        full_hash="F",
        created_by="mo",
        target_host_id=HOST,
    )
    # entry_id 1 drifted; entry_id 2 is clean.
    verify = VerifyReport(drifted={"1": "size_changed"})

    dispatched: list[SignedJob] = []

    async def execute_dispatch(signed: SignedJob) -> ExecuteOutcome:
        dispatched.append(signed)
        return ExecuteOutcome(
            results=[(str(i.entry_id), i.action.value, "quarantined") for i in signed.job.items],
            audit=[],
        )

    results = await orch.execute(plan, verify, host_id=HOST, dispatch=execute_dispatch)
    assert len(dispatched) == 1
    signed_items = [str(i.entry_id) for i in dispatched[0].job.items]
    assert signed_items == ["2"]  # the drifted "1" was dropped, never dispatched
    assert [r[0] for r in results] == ["2"]


async def test_execute_skips_when_all_drifted() -> None:
    orch, sink = _orch()
    plan = orch.build(
        plan_id="p3",
        members=_members(3),
        keep_id=0,
        full_hash="F",
        created_by="mo",
        target_host_id=HOST,
    )
    verify = VerifyReport(drifted={"1": "size_changed", "2": "became_symlink"})

    async def execute_dispatch(_signed: SignedJob) -> ExecuteOutcome:
        raise AssertionError("dispatch must not be called when everything drifted")

    results = await orch.execute(plan, verify, host_id=HOST, dispatch=execute_dispatch)
    assert results == []
    assert any(r.action == "remediation.execute.skip" for r in sink)  # type: ignore[attr-defined]


async def test_execute_over_blast_cap_requires_confirm() -> None:
    orch, _sink = _orch(blast_cap=1)
    plan = orch.build(
        plan_id="p4",
        members=_members(4),  # 3 actionable items > cap of 1
        keep_id=0,
        full_hash="F",
        created_by="mo",
        target_host_id=HOST,
    )
    verify = VerifyReport()  # nothing drifted

    async def execute_dispatch(signed: SignedJob) -> ExecuteOutcome:
        return ExecuteOutcome(
            results=[(str(i.entry_id), i.action.value, "quarantined") for i in signed.job.items],
            audit=[],
        )

    with pytest.raises(BlastCapExceededError):
        await orch.execute(plan, verify, host_id=HOST, dispatch=execute_dispatch)
    # With explicit confirmation the same plan proceeds.
    results = await orch.execute(
        plan, verify, host_id=HOST, confirm_blast=True, dispatch=execute_dispatch
    )
    assert len(results) == 3


async def test_dry_run_dispatches_signed_job_and_audits() -> None:
    orch, sink = _orch()
    plan = orch.build(
        plan_id="p5",
        members=_members(2),
        keep_id=0,
        full_hash="F",
        created_by="mo",
        target_host_id=HOST,
    )
    seen: list[SignedJob] = []

    async def dry_run_dispatch(signed: SignedJob) -> VerifyReport:
        seen.append(signed)
        assert signed.job.mode == "dry_run"
        return VerifyReport()

    report = await orch.dry_run(plan, host_id=HOST, dispatch=dry_run_dispatch)
    assert report.ok
    assert len(seen) == 1
    assert verify_chain(sink) is True
    assert any(r.action == "remediation.dry_run.dispatch" for r in sink)  # type: ignore[attr-defined]
