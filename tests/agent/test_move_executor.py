"""Reversible MOVE action tests (ADR-023) — the Organize apply executor.

Everything runs on THROWAWAY files in a tmp sandbox; the executor is default-disabled and the
dry-run path is asserted to mutate nothing. Covers the happy path + reversibility, the dry-run
simulation, and the adversarial gates: no-clobber, symlink-in-destination, content drift, and
default-disabled.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fathom.agent.actor import Executor, RemediationDisabledError, dry_run_verify
from fathom.agent.reader.hasher import BackendHasher
from fathom.backends import PosixBackend
from fathom.core.audit import AuditChain, verify_chain
from fathom.core.remediation.plan import PlanAction, PlanItem, RemediationPlan


def _audit() -> tuple[AuditChain, list]:
    sink: list = []
    return AuditChain(sink=sink.append), sink


def _build_move_plan(
    root: Path, src: Path, dest_rel: str, prior_hash: str | None
) -> RemediationPlan:
    st = src.stat()
    item = PlanItem(
        entry_id="f1",
        path=str(src),
        prior_inode=st.st_ino,
        prior_size=st.st_size,
        prior_hash=prior_hash,
        action=PlanAction.MOVE,
        dest_rel=dest_rel,
    )
    return RemediationPlan(
        plan_id="m1", created_by="mo", keeper_path=str(root), items=[item], move_root=str(root)
    )


async def _move_plan(
    root: Path, src: Path, dest_rel: str, *, with_hash: bool = False
) -> RemediationPlan:
    prior_hash = await BackendHasher(PosixBackend()).full(str(src)) if with_hash else None
    return _build_move_plan(root, src, dest_rel, prior_hash)


def _exec(root: Path, audit: AuditChain) -> Executor:
    return Executor(quarantine_dir=root / ".quarantine", audit=audit, write_enabled=True)


# --- happy path + reversibility ---------------------------------------------------------


async def test_move_relocates_preserving_inode_and_audits(tmp_path: Path) -> None:
    src = tmp_path / "messy.txt"
    src.write_bytes(b"hello organize" * 100)
    original_inode = src.stat().st_ino

    plan = await _move_plan(tmp_path, src, "sorted/2026/tidy-name.txt", with_hash=True)
    report = await dry_run_verify(plan, BackendHasher(PosixBackend()))
    assert report.ok

    audit, sink = _audit()
    results = await _exec(tmp_path, audit).execute(plan, report)

    assert [r.status for r in results] == ["moved"]
    dest = tmp_path / "sorted" / "2026" / "tidy-name.txt"
    assert dest.exists()
    assert not src.exists()  # moved, not copied
    assert dest.stat().st_ino == original_inode  # same inode → reversible by linking back
    assert dest.read_bytes() == b"hello organize" * 100  # content intact
    assert verify_chain(sink) is True
    assert len(sink) == 2  # audit-before-act + result (the (from,to) is on the chain)


# --- the "simulate moving, ensure nothing broken" guarantee -----------------------------


async def test_dry_run_simulates_without_moving(tmp_path: Path) -> None:
    src = tmp_path / "keep-me.txt"
    src.write_bytes(b"do not move me")
    plan = await _move_plan(tmp_path, src, "elsewhere/keep-me.txt", with_hash=True)

    report = await dry_run_verify(plan, BackendHasher(PosixBackend()))

    assert report.ok  # the plan verifies clean
    assert src.exists()  # ... and the dry-run moved NOTHING
    assert src.read_bytes() == b"do not move me"
    assert not (tmp_path / "elsewhere").exists()


# --- adversarial gates ------------------------------------------------------------------


async def test_move_no_clobber(tmp_path: Path) -> None:
    src = tmp_path / "a.txt"
    src.write_bytes(b"source")
    (tmp_path / "dest").mkdir()
    (tmp_path / "dest" / "taken.txt").write_bytes(b"already here")  # the target name is occupied

    plan = await _move_plan(tmp_path, src, "dest/taken.txt", with_hash=True)
    report = await dry_run_verify(plan, BackendHasher(PosixBackend()))
    audit, _ = _audit()
    results = await _exec(tmp_path, audit).execute(plan, report)

    assert results[0].status == "aborted_drift"
    assert "no-clobber" in results[0].detail
    assert src.exists()  # source untouched
    assert (tmp_path / "dest" / "taken.txt").read_bytes() == b"already here"  # not overwritten


async def test_move_refuses_symlinked_destination_component(tmp_path: Path) -> None:
    # A symlink planted in the destination tree must not redirect the move out of the root.
    src = tmp_path / "secret.txt"
    src.write_bytes(b"secret")
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "evil").symlink_to(outside)  # move_root/evil -> outside

    plan = await _move_plan(tmp_path, src, "evil/landed.txt", with_hash=True)
    report = await dry_run_verify(plan, BackendHasher(PosixBackend()))
    audit, _ = _audit()
    results = await _exec(tmp_path, audit).execute(plan, report)

    assert results[0].status == "aborted_drift"  # O_NOFOLLOW on the symlink component aborts
    assert src.exists()  # source untouched
    assert not (outside / "landed.txt").exists()  # nothing escaped the root


async def test_move_aborts_on_content_drift(tmp_path: Path) -> None:
    src = tmp_path / "drift.txt"
    src.write_bytes(b"original" * 10)
    plan = await _move_plan(tmp_path, src, "dst/drift.txt", with_hash=True)
    report = await dry_run_verify(plan, BackendHasher(PosixBackend()))
    # Tamper AFTER planning + verify, before execute (same length → only the hash catches it).
    src.write_bytes(b"tampered" * 10)
    audit, _ = _audit()
    results = await _exec(tmp_path, audit).execute(plan, report)
    assert results[0].status == "aborted_drift"
    assert src.exists()


async def test_move_disabled_by_default(tmp_path: Path) -> None:
    src = tmp_path / "x.txt"
    src.write_bytes(b"x")
    plan = await _move_plan(tmp_path, src, "d/x.txt")
    report = await dry_run_verify(plan, BackendHasher(PosixBackend()))
    ex = Executor(quarantine_dir=tmp_path / "q", audit=_audit()[0])  # write_enabled defaults False
    with pytest.raises(RemediationDisabledError):
        await ex.execute(plan, report)
    assert src.exists()


async def test_move_rejects_traversal_destination(tmp_path: Path) -> None:
    src = tmp_path / "y.txt"
    src.write_bytes(b"y")
    # A '..' dest_rel must be refused by the executor even though the plan was constructed with it.
    plan = await _move_plan(tmp_path, src, "../escape.txt")
    report = await dry_run_verify(plan, BackendHasher(PosixBackend()))
    audit, _ = _audit()
    results = await _exec(tmp_path, audit).execute(plan, report)
    assert results[0].status == "aborted_drift"
    assert "invalid destination" in results[0].detail
    assert src.exists()
    assert not (tmp_path.parent / "escape.txt").exists()
