"""Guarded remediation executor (ADD 02 §Mode 3, ADR-011).

The single destructive surface, hedged on every side:

* **Default-disabled** — does nothing unless ``write_enabled=True``.
* **Drift-gated** — refuses any plan whose dry-run verification is not OK.
* **Blast-radius cap** — refuses oversized plans unless explicitly confirmed (AR-0004/E-1).
* **TOCTOU-resistant** — operates on a parent directory fd + name, re-stats *and re-hashes*
  the target through that fd immediately before acting, and aborts on a symlink or
  inode/size/**content-hash** drift (inode+size alone cannot catch a same-length in-place
  overwrite; defeats path-swap and content-swap races — ADD 02, STRIDE T-2). An
  irreversible hard-delete with no hash anchor is refused outright.
* **Quarantine-first** — the default action is a reversible move to a quarantine tier;
  irreversible hard-delete additionally requires ``allow_hard_delete``.
* **Audit-before-act** — an audit record is chained *before* the mutation; no audit, no
  action (AR-0012).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import stat as stat_mod
from dataclasses import dataclass
from pathlib import Path

import blake3

from fathom.agent.actor.planner import VerifyReport
from fathom.core.audit import AuditChain, AuditRecord
from fathom.core.remediation.plan import PlanAction, PlanItem, RemediationPlan
from fathom.logging import get_logger

_log = get_logger("fathom.agent.actor.executor")

DEFAULT_BLAST_CAP = 100
_HASH_CHUNK_BYTES = 1 << 20


def _full_hash_through_fd(dir_fd: int, name: str) -> str:
    """BLAKE3 of the file's full content, opened *through* the validated parent ``dir_fd``
    with ``O_NOFOLLOW``.

    The bytes hashed are the same filesystem object the recheck just validated — the path
    is never re-resolved, so there is no second TOCTOU window. Matches the hex digest of
    ``reader.hasher.full_digest`` so it can be compared against ``PlanItem.prior_hash``.
    """
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        h = blake3.blake3()
        while True:
            block = os.read(fd, _HASH_CHUNK_BYTES)
            if not block:
                break
            h.update(block)
        return h.hexdigest()
    finally:
        os.close(fd)


class RemediationDisabledError(RuntimeError):
    """Raised when execute is attempted while ``write_enabled`` is False."""


class BlastRadiusError(RuntimeError):
    """Raised when a plan exceeds the blast-radius cap without explicit confirmation."""


@dataclass(frozen=True, slots=True)
class ExecResult:
    """Outcome of acting on a single plan item."""

    entry_id: str
    action: str
    status: str  # quarantined | deleted | aborted_drift | skipped_disabled
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ExecOutcome:
    """The full outcome of an :meth:`Executor.execute` run.

    ``results`` is the per-item status list; ``audit`` is the ordered list of hash-chained
    :class:`~fathom.core.audit.AuditRecord`s the executor emitted (audit-before-act + result per
    acted item). Core appends ``audit`` to the **durable** hash-chained store so the destructive
    act itself is on the tamper-evident chain, not only the actor's in-memory sink (security-review
    fix (2); see :func:`fathom.core.audit_store.append_records_durable`).
    """

    results: list[ExecResult]
    audit: list[AuditRecord]


class Executor:
    """Executes an approved, drift-verified plan with quarantine-first semantics."""

    def __init__(
        self,
        *,
        quarantine_dir: str | Path,
        audit: AuditChain,
        write_enabled: bool = False,
        blast_cap: int = DEFAULT_BLAST_CAP,
        allow_hard_delete: bool = False,
        actor: str = "strata-actor",
    ) -> None:
        self._quarantine_dir = Path(quarantine_dir)
        self._audit = audit
        self._write_enabled = write_enabled
        self._blast_cap = blast_cap
        self._allow_hard_delete = allow_hard_delete
        self._actor = actor

    async def execute(
        self, plan: RemediationPlan, verify: VerifyReport, *, confirm_blast: bool = False
    ) -> list[ExecResult]:
        """Execute ``plan`` after its dry-run ``verify``. Returns a per-item result list.

        The destructive act's audit records are also produced; :meth:`execute_with_audit` returns
        them so core can persist them on the durable hash-chained store (fix (2)). This thin
        wrapper preserves the original signature for callers that only need the result list.
        """
        return (await self.execute_with_audit(plan, verify, confirm_blast=confirm_blast)).results

    async def execute_with_audit(
        self, plan: RemediationPlan, verify: VerifyReport, *, confirm_blast: bool = False
    ) -> ExecOutcome:
        """Execute ``plan`` and return both the per-item results and the emitted audit records.

        The audit records are the same ones appended to the executor's injected in-memory
        :class:`~fathom.core.audit.AuditChain` (audit-before-act + result per acted item). Core
        re-chains and persists them via
        :func:`fathom.core.audit_store.append_records_durable`, putting the destructive act on the
        tamper-evident durable chain (security-review fix (2)).
        """
        if not self._write_enabled:
            raise RemediationDisabledError(
                "remediation is disabled (write_enabled=False); refusing to act"
            )
        if not verify.ok:
            raise ValueError(f"refusing to execute a drifted plan: {sorted(verify.drifted)}")
        if len(plan.items) > self._blast_cap and not confirm_blast:
            raise BlastRadiusError(
                f"plan touches {len(plan.items)} items > cap {self._blast_cap}; "
                "explicit confirmation required"
            )
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        # Actor-owned + restricted (0o700): the quarantine dir holds reversible-tier originals, the
        # local act-audit, and the nonce ledger; enforce the "restricted" claim in code (not just
        # deployment ACLs). chmod covers a pre-existing dir that mkdir(exist_ok) would not re-perm.
        self._quarantine_dir.chmod(0o700)
        results: list[ExecResult] = []
        audit: list[AuditRecord] = []
        # Items are acted on sequentially (each await completes before the next starts), so the
        # shared in-memory AuditChain head advances in order and the collected ``audit`` list is
        # the chain in append order — safe to hand to the durable store.
        for item in plan.items:
            result, records = await asyncio.to_thread(self._act, plan, item)
            results.append(result)
            audit.extend(records)
        return ExecOutcome(results=results, audit=audit)

    def _act(self, plan: RemediationPlan, item: PlanItem) -> tuple[ExecResult, list[AuditRecord]]:
        """Perform one item's action in a worker thread, with the TOCTOU re-check and audit.

        Returns the per-item result and the audit records emitted for it (empty when the item
        aborted on drift before any audit-before-act record was written — nothing acted, nothing
        audited).
        """
        entry_id = str(item.entry_id)
        target = Path(item.path)
        parent = str(target.parent)
        name = target.name
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            drift = self._recheck(dir_fd, name, item)
            if drift is not None:
                return ExecResult(entry_id, item.action.value, "aborted_drift", drift), []

            before: dict[str, object] = {
                "inode": item.prior_inode,
                "size": item.prior_size,
                "hash": item.prior_hash,
            }
            # Audit-before-act: record intent first; the mutation follows only after this.
            records = [
                self._audit.append(
                    actor=self._actor,
                    action=item.action.value,
                    target=item.path,
                    before_state=before,
                    result="pending",
                )
            ]
            status, detail = self._mutate(dir_fd, name, plan, item)
            records.append(
                self._audit.append(
                    actor=self._actor,
                    action=item.action.value,
                    target=item.path,
                    before_state=before,
                    result=status,
                )
            )
            return ExecResult(entry_id, item.action.value, status, detail), records
        finally:
            os.close(dir_fd)

    @staticmethod
    def _recheck(dir_fd: int, name: str, item: PlanItem) -> str | None:
        """Re-verify the target through the parent fd immediately before acting.

        Inode + size are necessary but NOT sufficient to bind content: a same-length
        in-place overwrite preserves both, so an inode/size-only gate would let the actor
        delete bytes that no longer match what was approved (STRIDE T-2). The final
        fd-anchored gate therefore re-hashes the content too. The hash is read through the
        same validated ``dir_fd``/``O_NOFOLLOW`` open as everything else — no path
        re-resolution. An irreversible HARD_DELETE with no hash anchor at all is refused
        (fail-closed): we never destroy what we cannot prove is the approved duplicate.
        """
        try:
            st = os.lstat(name, dir_fd=dir_fd)
        except OSError:
            return "missing"
        if stat_mod.S_ISLNK(st.st_mode):
            return "became_symlink"
        if st.st_ino != item.prior_inode:
            return "inode_changed"
        if st.st_size != item.prior_size:
            return "size_changed"
        if item.prior_hash is not None:
            try:
                current = _full_hash_through_fd(dir_fd, name)
            except OSError:
                return "hash_unreadable"
            if current != item.prior_hash:
                return "hash_changed"
        elif item.action is PlanAction.HARD_DELETE:
            return "no_hash_anchor"
        return None

    def _mutate(
        self, dir_fd: int, name: str, plan: RemediationPlan, item: PlanItem
    ) -> tuple[str, str]:
        if item.action is PlanAction.QUARANTINE:
            dest_name = f"{plan.plan_id}__{item.prior_inode}__{name}"
            q_fd = os.open(self._quarantine_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.rename(name, dest_name, src_dir_fd=dir_fd, dst_dir_fd=q_fd)
            except OSError as exc:
                # e.g. EXDEV when the quarantine dir is on a different filesystem, or any other
                # rename failure. Report per-item and continue the batch (a result audit still
                # follows the pending record) — never let one item abort every remaining one.
                return "aborted_drift", f"quarantine refused (errno {exc.errno})"
            finally:
                os.close(q_fd)
            return "quarantined", str(self._quarantine_dir / dest_name)
        if item.action is PlanAction.HARD_DELETE:
            if not self._allow_hard_delete:
                return "skipped_disabled", "hard_delete requires allow_hard_delete"
            try:
                os.unlink(name, dir_fd=dir_fd)
            except OSError as exc:
                return "aborted_drift", f"hard_delete refused (errno {exc.errno})"
            return "deleted", ""
        if item.action is PlanAction.MOVE:
            return self._move(dir_fd, name, plan, item)
        # HARDLINK is designed but not part of the v1 spine.
        return "skipped_disabled", f"action {item.action.value} not implemented in v1"

    def _move(
        self, src_dir_fd: int, src_name: str, plan: RemediationPlan, item: PlanItem
    ) -> tuple[str, str]:
        """Relocate the validated source to ``dest_rel`` under the plan's ``move_root`` (ADR-023).

        Reversible + no-clobber + symlink-safe: the destination directory is walked component by
        component from ``move_root`` with ``O_NOFOLLOW`` (a planted symlink cannot redirect the
        move out of the approved root), the file is placed with an atomic ``link`` that fails if the
        target name already exists (no overwrite), then the source name is unlinked — so the inode
        is preserved at the new path and the original ``(from,to)`` is on the audit chain, making
        the move a one-step undo. Same-volume only: a cross-filesystem ``link`` fails ``EXDEV`` and
        is refused rather than silently degraded.
        """
        if not plan.move_root or not item.dest_rel:
            return "skipped_disabled", "move requires move_root + dest_rel"
        parts = [p for p in item.dest_rel.split("/") if p]
        if not parts or any(p in {"..", "."} for p in parts):
            return "aborted_drift", "invalid destination"
        *dirs, leaf = parts
        opened: list[int] = []
        try:
            cur = os.open(plan.move_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            opened.append(cur)
            for component in dirs:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(component, dir_fd=cur)
                # O_NOFOLLOW per component: an existing symlink here raises and aborts the move,
                # so the destination can never be redirected outside the approved root.
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur)
                opened.append(nxt)
                cur = nxt
            try:
                os.link(
                    src_name, leaf, src_dir_fd=src_dir_fd, dst_dir_fd=cur, follow_symlinks=False
                )
            except FileExistsError:
                return "aborted_drift", "destination already exists (no-clobber)"
            except OSError as exc:
                return "aborted_drift", f"move refused (errno {exc.errno})"
            try:
                os.unlink(src_name, dir_fd=src_dir_fd)
            except OSError as exc:
                # The link succeeded but removing the source did not: leaving it would create a
                # duplicate AND report 'aborted' (nothing changed), which is false. Roll back the
                # just-created destination leaf (best-effort) so on-disk state matches the result.
                with contextlib.suppress(OSError):
                    os.unlink(leaf, dir_fd=cur)
                return "aborted_drift", f"move source-unlink failed (errno {exc.errno})"
            return "moved", f"{plan.move_root.rstrip('/')}/{item.dest_rel}"
        except OSError as exc:
            return "aborted_drift", f"move setup failed (errno {exc.errno})"
        finally:
            for fd in reversed(opened):
                os.close(fd)
