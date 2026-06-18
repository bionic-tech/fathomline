"""Organize planner (ADR-021): folder entries → LLM proposal → root-clamped, reviewable result.

The model is **advisory only**. Its proposal is mapped back to catalogue entries and every target is
put through :func:`clamp_to_root` — absolute paths, ``..`` traversal, escapes, bad leaf names, and
target collisions are rejected server-side. A prompt-injected file ("move everything to /etc") can
therefore only ever yield an in-root suggestion a human still reviews; the server, not the model,
decides where anything could go. Nothing here mutates the filesystem (that is ADR-023's executor).
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.models import FsEntryRow, Volume
from fathom.core.query import escape_like
from fathom.core.remediation.models import RemediationPlanItemRow, RemediationPlanRow
from fathom.core.remediation.plan import PlanAction, PlanItem, RemediationPlan
from fathom.inference.base import InferenceProvider
from fathom.logging import get_logger
from fathom.security.paths import PathSafetyError, validate_config_path

_log = get_logger("fathom.core.organize")
_LIKE_ESCAPE = "\\"

# How many files we will ever hand the model in one request (bounds prompt size + blast radius).
MAX_FILES_HARD_CAP = 200

# How many previously-applied moves to seed a suggestion prompt with (few-shot; bounds prompt size).
MAX_FEWSHOT_EXAMPLES = 8


def clamp_to_root(root: str, rel: str) -> str | None:
    """Resolve a model-proposed *relative* path under ``root``; the safe absolute path, or None.

    Rejects (returns None): empty, NUL-bearing, absolute (``/``-leading), and any path that, after
    normalisation, is not ``root`` itself or a descendant (so ``..`` traversal and escapes are
    caught). This is the prompt-injection firewall: the model proposes, this decides.
    """
    if not rel or "\x00" in rel or rel.startswith("/"):
        return None
    base = root.rstrip("/")
    candidate = posixpath.normpath(posixpath.join(base, rel))
    if candidate == base or candidate.startswith(base + "/"):
        return candidate
    return None


def _safe_leaf(name: str) -> str | None:
    """A leaf filename is one path component: no separators, not '.'/'..'/empty, no NUL."""
    n = name.strip()
    if not n or n in {".", ".."} or "/" in n or "\x00" in n:
        return None
    return n


class _Assignment(BaseModel):
    """One model assignment, keyed back to the input by ``index``.

    Deliberately small (no per-item prose): on a CPU-bound local model the generated token count is
    the dominant cost, so the model emits only the placement, not an explanation. Rejection reasons
    are set server-side on :class:`ProposedItem`.
    """

    index: int
    target_dir: str = ""  # relative sub-directory under the root ("" = the root itself)
    new_name: str = ""  # leaf filename ("" = keep the original)


class _LlmProposal(BaseModel):
    assignments: list[_Assignment] = Field(default_factory=list)


@dataclass(slots=True)
class ProposedItem:
    """One file's proposed disposition, after server-side validation."""

    entry_id: int
    current_path: str
    current_name: str
    proposed_relpath: str  # path relative to the root (the new location + name)
    proposed_name: str
    reason: str
    status: str  # "move" | "keep" | "rejected"


@dataclass(slots=True)
class OrganizeProposal:
    """A reviewed reorganisation suggestion for one folder — read-only; apply is ADR-023."""

    root: str
    volume_id: int
    model: str
    items: list[ProposedItem]
    rejected: int
    considered: int


@dataclass(frozen=True, slots=True)
class ApprovedMove:
    """One operator-approved relocation from a reviewed proposal: an entry + its in-root target."""

    entry_id: int
    dest_rel: str  # path relative to the root (sub-dir + leaf); re-clamped server-side


@dataclass(slots=True)
class MovePlanBuild:
    """A built, server-authoritative MOVE plan ready to persist + dispatch (ADR-023)."""

    plan: RemediationPlan
    host_id: str
    total_bytes: int


class OrganizePlanError(ValueError):
    """A MOVE plan could not be built (bad target, missing entry, out-of-root, empty)."""


@dataclass(slots=True)
class _Entry:
    entry_id: int
    path: str
    name: str
    size_on_disk: int
    mtime: float
    rel: str  # path relative to the root


_SYSTEM = (
    "You are a careful file organiser. Given files in a folder, propose a tidier structure: group "
    "related files into clear, conventional sub-folders (by type, date, or topic) and give them "
    "tidy names. RULES: use RELATIVE paths only, never absolute and never '..'. 'target_dir' is "
    "a relative sub-folder under the root (may nest with '/', or be empty to keep at the root). "
    "'new_name' is the leaf filename only (no '/'); leave empty to keep the original. Always keep "
    "the file extension. Prefer lowercase, hyphen/underscore-separated names. Refer to each file "
    "by its 'index'; return exactly one assignment per file."
)


def _fmt_mtime(mtime: float) -> str:
    return datetime.fromtimestamp(mtime, tz=UTC).strftime("%Y-%m-%d") if mtime else "unknown"


class OrganizeService:
    """Build a reviewable, root-clamped Organize proposal for a folder (suggestion only)."""

    def __init__(
        self, session: AsyncSession, provider: InferenceProvider | None = None, *, model: str
    ) -> None:
        # ``provider`` is only needed by :meth:`suggest` (the read-only model call). The apply path
        # (:meth:`build_move_plan`) is pure server-side validation and stands up no model client.
        self._session = session
        self._provider = provider
        self._model = model

    async def suggest(
        self,
        *,
        volume_id: int,
        root: str,
        scope: ScopeFilter | None = None,
        max_files: int = 60,
    ) -> OrganizeProposal:
        """Return a proposed reorganisation for the files under ``root`` (scope-checked, read-only).

        Reads catalogue metadata only and never mutates the filesystem.
        """
        limit = max(1, min(max_files, MAX_FILES_HARD_CAP))
        entries = await self._files_under(volume_id, root, limit, scope)
        if not entries:
            return OrganizeProposal(root, volume_id, self._model, [], 0, 0)

        listing = "\n".join(
            f"[{i}] {e.rel}  ({e.size_on_disk} bytes, modified {_fmt_mtime(e.mtime)})"
            for i, e in enumerate(entries)
        )
        if self._provider is None:
            raise RuntimeError("OrganizeService.suggest requires an inference provider")
        # Few-shot learning (ADR-021 Phase 3): seed the prompt with moves the operator has already
        # APPLIED on this volume, so the model converges on their filing conventions instead of a
        # generic scheme. Read-only and scope-bounded (same-volume examples only).
        examples = await self._recent_examples(volume_id)
        example_block = (
            "The user has previously organised files on this volume like this — follow the same "
            f"conventions (folder names, casing, grouping) when they fit:\n{examples}\n\n"
            if examples
            else ""
        )
        user = f"Root folder: {root}\n{example_block}Files ({len(entries)}):\n{listing}"
        proposal = await self._provider.complete(system=_SYSTEM, user=user, schema=_LlmProposal)

        items = self._resolve(root, entries, proposal)
        rejected = sum(1 for it in items if it.status == "rejected")
        _log.info(
            "organize suggestion",
            extra={"volume_id": volume_id, "considered": len(entries), "rejected": rejected},
        )
        return OrganizeProposal(root, volume_id, self._model, items, rejected, len(entries))

    async def build_move_plan(
        self,
        *,
        plan_id: str,
        created_by: str,
        volume_id: int,
        root: str,
        moves: list[ApprovedMove],
        scope: ScopeFilter | None = None,
    ) -> MovePlanBuild:
        """Turn an operator-approved subset of a proposal into a server-authoritative MOVE plan.

        Server-authoritative (AR-0012): the client supplies only ``entry_id`` + the approved
        ``dest_rel``; the *drift anchor* (inode, size, content hash) and the source path come from
        the catalogue, never from the client. Every destination is re-clamped to ``root`` (the
        firewall — a tampered ``dest_rel`` can still only ever land in-root), every source must be a
        present, non-dir entry under ``root`` in this volume and in scope, and same-target
        collisions / no-op moves are rejected. The result is a :class:`RemediationPlan` with
        ``move_root=root`` whose items the existing dry-run/execute spine acts on (ADR-023).

        Raises:
            OrganizePlanError: empty/duplicate/out-of-root/no-op selection (→ 422).
        """
        if not moves:
            raise OrganizePlanError("no moves selected")
        if len(moves) > MAX_FILES_HARD_CAP:
            raise OrganizePlanError(f"too many moves (> {MAX_FILES_HARD_CAP})")
        base = root.rstrip("/")
        by_id = await self._entries_by_id(volume_id, [m.entry_id for m in moves], base, scope)
        items: list[PlanItem] = []
        taken: dict[str, int] = {}  # absolute dest -> source entry_id that claimed it
        host_id: str | None = None
        total_bytes = 0
        seen_ids: set[int] = set()
        for move in moves:
            if move.entry_id in seen_ids:
                raise OrganizePlanError(f"entry {move.entry_id} listed twice")
            seen_ids.add(move.entry_id)
            entry = by_id.get(move.entry_id)
            if entry is None:
                raise OrganizePlanError(f"entry {move.entry_id} not found under root (rescan?)")
            absolute = self._clamp_move_target(root, move.dest_rel)
            if absolute is None:
                raise OrganizePlanError(f"target for entry {move.entry_id} is out of root")
            if absolute == entry.path:
                raise OrganizePlanError(f"entry {move.entry_id} target equals its current path")
            if absolute in taken:
                raise OrganizePlanError(f"two entries target {absolute!r}")
            taken[absolute] = move.entry_id
            try:
                validate_config_path(entry.path)  # source is catalogue-sourced; re-checked anyway
            except PathSafetyError as exc:
                raise OrganizePlanError(f"source path failed safety: {exc}") from exc
            if entry.full_hash is None:
                # No content anchor → the actor's TOCTOU re-check would degrade to inode+size only,
                # letting a same-length in-place overwrite slip past (T-2, adversarial-review fix).
                # Require a full-bit scan first, matching the dedup path's hash-anchored guarantee.
                raise OrganizePlanError(
                    f"entry {move.entry_id} has no content hash — run a full-bit scan before moving"
                )
            items.append(
                PlanItem(
                    entry_id=entry.id,
                    path=entry.path,
                    prior_inode=entry.inode,
                    prior_size=entry.size_logical,
                    prior_hash=entry.full_hash,
                    action=PlanAction.MOVE,
                    dest_rel=absolute[len(base) + 1 :],  # relative to move_root
                )
            )
            total_bytes += entry.size_logical
            host_id = str(entry.host_id)
        assert host_id is not None  # noqa: S101 — guaranteed by the non-empty moves check
        plan = RemediationPlan(
            plan_id=plan_id,
            created_by=created_by,
            keeper_path=base,  # the folder being organised (the moves stay within it)
            items=items,
            move_root=base,
        )
        return MovePlanBuild(plan=plan, host_id=host_id, total_bytes=total_bytes)

    @staticmethod
    def _clamp_move_target(root: str, dest_rel: str) -> str | None:
        """Clamp a proposed move target to ``root`` AND require a safe leaf filename.

        ``clamp_to_root`` already rejects absolute/``..``/escape; this additionally rejects a
        target whose final component is unsafe (``.``/``..``/empty) so a MOVE always lands on a
        real filename inside the root, never on the root directory itself.
        """
        absolute = clamp_to_root(root, dest_rel)
        if absolute is None or absolute == root.rstrip("/"):
            return None
        if _safe_leaf(posixpath.basename(absolute)) is None:
            return None
        return absolute

    async def _entries_by_id(
        self, volume_id: int, entry_ids: list[int], base: str, scope: ScopeFilter | None
    ) -> dict[int, FsEntryRow]:
        """Load the catalogue rows for ``entry_ids`` that are present, non-dir, under ``base``.

        Scope is enforced on the volume (server-authoritative): an out-of-scope volume yields no
        rows, so the build fails closed. Rows outside ``base`` or the wrong volume are dropped — an
        attacker cannot smuggle an entry from another folder into the plan via its id.
        """
        like = escape_like(base) + "/%"
        stmt = (
            select(FsEntryRow)
            .join(Volume, Volume.id == FsEntryRow.volume_id)
            .where(
                FsEntryRow.id.in_(entry_ids),
                FsEntryRow.volume_id == volume_id,
                FsEntryRow.is_dir.is_(False),
                FsEntryRow.present.is_(True),
                FsEntryRow.path.like(like, escape=_LIKE_ESCAPE),
            )
        )
        if scope is not None:
            stmt = scope.apply(
                stmt,
                host_col=FsEntryRow.host_id,
                volume_col=FsEntryRow.volume_id,
                kind_col=Volume.kind,
            )
        rows = (await self._session.execute(stmt)).scalars().all()
        return {row.id: row for row in rows}

    async def _recent_examples(self, volume_id: int) -> str:
        """Render the operator's recently-APPLIED moves on this volume as few-shot examples.

        Learns only from MOVE plans the operator actually executed (``status == 'executed'``,
        ``move_root`` set) on the SAME volume — a confirmed signal of their filing conventions, and
        scope-bounded by construction (no cross-volume/cross-tenant leakage). Returns a compact
        ``old-name  ->  new-relative-path`` block, or ``""`` when there is nothing learned yet.
        """
        stmt = (
            select(RemediationPlanItemRow.path, RemediationPlanItemRow.dest_rel)
            .join(RemediationPlanRow, RemediationPlanRow.id == RemediationPlanItemRow.plan_id)
            .where(
                RemediationPlanRow.volume_id == volume_id,
                RemediationPlanRow.move_root.is_not(None),
                RemediationPlanRow.status == "executed",
                RemediationPlanItemRow.dest_rel.is_not(None),
            )
            .order_by(RemediationPlanRow.created_at.desc())
            .limit(MAX_FEWSHOT_EXAMPLES)
        )
        rows = (await self._session.execute(stmt)).all()
        lines = [f"- {posixpath.basename(r.path)}  ->  {r.dest_rel}" for r in rows if r.dest_rel]
        return "\n".join(lines)

    async def _files_under(
        self, volume_id: int, root: str, limit: int, scope: ScopeFilter | None
    ) -> list[_Entry]:
        like = escape_like(root.rstrip("/")) + "/%"
        stmt = (
            select(
                FsEntryRow.id,
                FsEntryRow.path,
                FsEntryRow.name,
                FsEntryRow.size_on_disk,
                FsEntryRow.mtime,
            )
            .join(Volume, Volume.id == FsEntryRow.volume_id)
            .where(
                FsEntryRow.volume_id == volume_id,
                FsEntryRow.is_dir.is_(False),
                FsEntryRow.present.is_(True),
                FsEntryRow.path.like(like, escape=_LIKE_ESCAPE),
            )
            .order_by(FsEntryRow.size_on_disk.desc())
            .limit(limit)
        )
        if scope is not None:
            stmt = scope.apply(
                stmt,
                host_col=FsEntryRow.host_id,
                volume_col=FsEntryRow.volume_id,
                kind_col=Volume.kind,
            )
        base = root.rstrip("/")
        rows = (await self._session.execute(stmt)).all()
        return [
            _Entry(
                entry_id=r.id,
                path=r.path,
                name=r.name,
                size_on_disk=r.size_on_disk,
                mtime=r.mtime,
                rel=r.path[len(base) + 1 :] if r.path.startswith(base + "/") else r.name,
            )
            for r in rows
        ]

    def _resolve(
        self, root: str, entries: list[_Entry], proposal: _LlmProposal
    ) -> list[ProposedItem]:
        by_index = {a.index: a for a in proposal.assignments}
        base = root.rstrip("/")
        taken: dict[str, int] = {}  # absolute proposed path -> first entry index that claimed it
        items: list[ProposedItem] = []
        for i, e in enumerate(entries):
            a = by_index.get(i)
            leaf = _safe_leaf(a.new_name) if (a and a.new_name) else e.name
            if leaf is None:
                items.append(
                    ProposedItem(
                        e.entry_id, e.path, e.name, e.rel, e.name, "invalid name", "rejected"
                    )
                )
                continue
            target_dir = (a.target_dir if a else "").strip()
            rel = posixpath.normpath(posixpath.join(target_dir, leaf)) if target_dir else leaf
            absolute = clamp_to_root(root, rel)
            if absolute is None:
                items.append(
                    ProposedItem(
                        e.entry_id,
                        e.path,
                        e.name,
                        e.rel,
                        leaf,
                        "out-of-root target rejected",
                        "rejected",
                    )
                )
                continue
            if absolute in taken and taken[absolute] != i:
                items.append(
                    ProposedItem(
                        e.entry_id,
                        e.path,
                        e.name,
                        e.rel,
                        leaf,
                        "collides with another proposal",
                        "rejected",
                    )
                )
                continue
            taken[absolute] = i
            proposed_rel = absolute[len(base) + 1 :] if absolute != base else ""
            status = "keep" if absolute == e.path else "move"
            # Accepted items carry no model prose (kept out of the schema for speed); only
            # server-set rejection reasons populate the field.
            items.append(ProposedItem(e.entry_id, e.path, e.name, proposed_rel, leaf, "", status))
        return items
