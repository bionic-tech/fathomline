"""Remediation safety-spine regression suite (AR-0006; STRIDE T-2/T-3, E-1).

These are the named tests ADR-011 requires to pass before any execute path is enabled.
Everything runs in a tmp sandbox; the executor is default-disabled and never wired to a
remotely reachable endpoint.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fathom.agent.actor import (
    BlastRadiusError,
    Executor,
    RemediationDisabledError,
    dry_run_verify,
)
from fathom.agent.reader.hasher import BackendHasher
from fathom.backends import PosixBackend
from fathom.core.audit import AuditChain, verify_chain
from fathom.core.remediation import Member, PlanAction, build_plan


def _audit() -> tuple[AuditChain, list]:
    sink: list = []
    return AuditChain(sink=sink.append), sink


def _member(path: Path, entry_id: str) -> Member:
    st = path.stat()
    return Member(entry_id=entry_id, path=str(path), inode=st.st_ino, size=st.st_size)


def _two_identical(tmp_path: Path) -> tuple[Path, Path]:
    a = tmp_path / "keep.bin"
    b = tmp_path / "dup.bin"
    a.write_bytes(b"X" * 4096)
    b.write_bytes(b"X" * 4096)
    return a, b


async def _plan_for(tmp_path: Path, action: PlanAction = PlanAction.QUARANTINE):
    a, b = _two_identical(tmp_path)
    backend = PosixBackend()
    full = await BackendHasher(backend).full(str(a))
    plan = build_plan(
        plan_id="p1",
        created_by="mo",
        members=[_member(a, "keep"), _member(b, "dup")],
        keep_id="keep",
        full_hash=full,
        action=action,
    )
    return plan, a, b, backend


# --- happy path -------------------------------------------------------------------------


async def test_quarantine_moves_file_and_audits(tmp_path: Path) -> None:
    plan, keep, dup, backend = await _plan_for(tmp_path)
    report = await dry_run_verify(plan, BackendHasher(backend))
    assert report.ok

    audit, sink = _audit()
    qdir = tmp_path / "quarantine"
    ex = Executor(quarantine_dir=qdir, audit=audit, write_enabled=True)
    results = await ex.execute(plan, report)

    assert [r.status for r in results] == ["quarantined"]
    assert not dup.exists()  # moved out
    assert keep.exists()  # keeper untouched
    assert list(qdir.iterdir())  # something landed in quarantine
    assert verify_chain(sink) is True
    assert len(sink) == 2  # audit-before-act + result


# --- E-1: blast radius & default-disabled ----------------------------------------------


async def test_disabled_by_default(tmp_path: Path) -> None:
    plan, _keep, dup, backend = await _plan_for(tmp_path)
    report = await dry_run_verify(plan, BackendHasher(backend))
    audit, _ = _audit()
    ex = Executor(quarantine_dir=tmp_path / "q", audit=audit)  # write_enabled defaults False
    with pytest.raises(RemediationDisabledError):
        await ex.execute(plan, report)
    assert dup.exists()  # nothing happened


async def test_blast_radius_cap(tmp_path: Path) -> None:
    plan, _keep, _dup, backend = await _plan_for(tmp_path)
    report = await dry_run_verify(plan, BackendHasher(backend))
    audit, _ = _audit()
    ex = Executor(quarantine_dir=tmp_path / "q", audit=audit, write_enabled=True, blast_cap=0)
    with pytest.raises(BlastRadiusError):
        await ex.execute(plan, report)


# --- T-3: tampered / stale plan ---------------------------------------------------------


async def test_drift_on_changed_content_aborts(tmp_path: Path) -> None:
    plan, _keep, dup, backend = await _plan_for(tmp_path)
    # Mutate the duplicate after the plan was built (size changes) → drift.
    dup.write_bytes(b"Y" * 8192)
    report = await dry_run_verify(plan, BackendHasher(backend))
    assert not report.ok
    assert report.drifted["dup"] in {"size_changed", "hash_changed", "inode_changed"}

    audit, _ = _audit()
    ex = Executor(quarantine_dir=tmp_path / "q", audit=audit, write_enabled=True)
    with pytest.raises(ValueError, match="drifted"):
        await ex.execute(plan, report)
    assert dup.exists()


async def test_hash_tamper_detected(tmp_path: Path) -> None:
    # Same size, different content after planning → only the hash check catches it.
    plan, _keep, dup, backend = await _plan_for(tmp_path)
    dup.write_bytes(b"Z" * 4096)  # identical size, different bytes
    report = await dry_run_verify(plan, BackendHasher(backend), verify_hash=True)
    assert not report.ok
    assert report.drifted["dup"] == "hash_changed"


# --- T-2: TOCTOU symlink swap -----------------------------------------------------------


async def test_symlink_swap_detected_at_verify(tmp_path: Path) -> None:
    plan, _keep, dup, backend = await _plan_for(tmp_path)
    dup.unlink()
    dup.symlink_to(tmp_path / "keep.bin")  # swap the target for a symlink
    report = await dry_run_verify(plan, BackendHasher(backend))
    assert report.drifted["dup"] in {"became_symlink", "inode_changed", "missing"}


async def test_symlink_swap_aborts_at_execute(tmp_path: Path) -> None:
    # Even if verification passed, a swap before the mutation is re-checked through the
    # parent fd and aborted — never followed.
    plan, _keep, dup, backend = await _plan_for(tmp_path)
    clean_report = await dry_run_verify(plan, BackendHasher(backend))
    assert clean_report.ok

    sensitive = tmp_path / "sensitive.txt"
    sensitive.write_text("do not touch")
    dup.unlink()
    dup.symlink_to(sensitive)

    audit, sink = _audit()
    ex = Executor(quarantine_dir=tmp_path / "q", audit=audit, write_enabled=True)
    results = await ex.execute(plan, clean_report)
    assert results[0].status == "aborted_drift"
    assert sensitive.exists() and sensitive.read_text() == "do not touch"
    assert sink == []  # nothing audited because nothing acted


# --- hard delete gating -----------------------------------------------------------------


async def test_hard_delete_requires_flag(tmp_path: Path) -> None:
    plan, _keep, dup, backend = await _plan_for(tmp_path, action=PlanAction.HARD_DELETE)
    report = await dry_run_verify(plan, BackendHasher(backend))
    audit, _ = _audit()
    ex = Executor(quarantine_dir=tmp_path / "q", audit=audit, write_enabled=True)
    results = await ex.execute(plan, report)
    assert results[0].status == "skipped_disabled"
    assert dup.exists()  # not deleted without allow_hard_delete

    audit2, _ = _audit()
    ex2 = Executor(
        quarantine_dir=tmp_path / "q",
        audit=audit2,
        write_enabled=True,
        allow_hard_delete=True,
    )
    # rebuild plan/report against current state
    results2 = await ex2.execute(plan, await dry_run_verify(plan, BackendHasher(backend)))
    assert results2[0].status == "deleted"
    assert not dup.exists()


async def test_content_swap_before_hard_delete_aborts(tmp_path: Path) -> None:
    # T-2 final gate: a same-length in-place overwrite AFTER a clean dry-run preserves inode
    # and size, so an inode/size-only recheck would still delete. The execute-time content
    # re-hash must catch it and abort — no irreversible delete of bytes that changed.
    plan, _keep, dup, backend = await _plan_for(tmp_path, action=PlanAction.HARD_DELETE)
    clean = await dry_run_verify(plan, BackendHasher(backend))
    assert clean.ok

    before_ino = dup.stat().st_ino
    with dup.open("r+b") as fh:  # overwrite in place: same inode, same size, different bytes
        fh.seek(0)
        fh.write(b"Z" * 4096)
    assert dup.stat().st_ino == before_ino and dup.stat().st_size == 4096

    audit, sink = _audit()
    ex = Executor(
        quarantine_dir=tmp_path / "q", audit=audit, write_enabled=True, allow_hard_delete=True
    )
    results = await ex.execute(plan, clean)
    assert results[0].status == "aborted_drift"
    assert results[0].detail == "hash_changed"
    assert dup.exists()  # NOT deleted — content no longer matches the approved hash
    assert sink == []  # nothing acted, so nothing audited


async def test_hard_delete_without_hash_anchor_refused(tmp_path: Path) -> None:
    # Fail-closed: an irreversible HARD_DELETE with no content anchor (prior_hash=None) is
    # refused — we never destroy what we cannot prove is the approved duplicate.
    plan, _keep, dup, backend = await _plan_for(tmp_path, action=PlanAction.HARD_DELETE)
    report = await dry_run_verify(plan, BackendHasher(backend))
    anchorless = plan.model_copy(
        update={"items": [it.model_copy(update={"prior_hash": None}) for it in plan.items]}
    )
    audit, sink = _audit()
    ex = Executor(
        quarantine_dir=tmp_path / "q", audit=audit, write_enabled=True, allow_hard_delete=True
    )
    results = await ex.execute(anchorless, report)
    assert results[0].status == "aborted_drift"
    assert results[0].detail == "no_hash_anchor"
    assert dup.exists()
    assert sink == []


def test_build_plan_requires_existing_keeper() -> None:
    with pytest.raises(ValueError, match="not a member"):
        build_plan(
            plan_id="p",
            created_by="mo",
            members=[Member("a", "/v/a", 1, 10)],
            keep_id="nope",
            full_hash="F",
        )
