"""Cross-host reconciliation (ADR-024): path-aligned divergence detection.

Given a **definitive** ``(volume, root)`` and a **comparison** ``(volume, root)``, match files by
their path *relative to each root* and classify every pair — identical, same-content-but-timestamp-
drifted, diverged (content differs → flag), size-match-but-unhashed (needs a full-bit scan), or
present-on-only-one-side. The classification + counts run **DB-side** (relative path computed with
``substr``, two scope-filtered subqueries joined on it) so it scales to multi-million-file trees
without loading them into the app, and stays portable across PostgreSQL and SQLite (no
``FULL OUTER JOIN``). Read-only: this proposes and moves nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import ColumnElement, Select, and_, case, func, literal, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import Subquery

from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.models import FsEntryRow, Volume
from fathom.core.query import escape_like
from fathom.logging import get_logger

_log = get_logger("fathom.core.reconcile")

_LIKE_ESCAPE = "\\"

# Reconcile matches files by their path *relative to each root*, joining both sides on that computed
# (un-indexed) relpath — an O(files-on-each-side) hash/merge join, run several times. Whole-pool vs
# whole-pool comparisons (millions x millions) therefore grind for minutes and look broken. Two
# guards keep it responsive: refuse a side larger than MAX_SIDE_ENTRIES (which also nudges the user
# toward the right usage — two copies of the SAME folder), and cap the comparison's DB time so even
# an under-cap-but-pathological run fails fast and cleanly instead of hanging.
MAX_SIDE_ENTRIES = 2_000_000
COMPARE_TIMEOUT_SECONDS = 60.0

# Classification labels (ADR-024). Stable strings — the API and UI key off them.
IDENTICAL = "identical"
CONTENT_SAME_META_DIFF = "content_same_meta_diff"
DIVERGED = "diverged"
SIZE_MATCH_UNHASHED = "size_match_unhashed"
MISSING_ON_COMPARISON = "missing_on_comparison"
MISSING_ON_DEFINITIVE = "missing_on_definitive"

ALL_CLASSES = (
    IDENTICAL,
    CONTENT_SAME_META_DIFF,
    DIVERGED,
    SIZE_MATCH_UNHASHED,
    MISSING_ON_COMPARISON,
    MISSING_ON_DEFINITIVE,
)

# Hard cap on the returned item sample (counts are always exact; the list is a bounded preview).
MAX_ITEMS = 500


class ReconcileTooLargeError(Exception):
    """A root holds more files than reconcile will compare in one pass (narrow to a subfolder).

    ``definitive_count`` / ``comparison_count`` are saturating counts (capped at ``cap + 1``), so a
    value of ``cap + 1`` means "more than cap"; the exact figure above the cap is not computed.
    """

    def __init__(self, *, definitive_count: int, comparison_count: int, cap: int) -> None:
        self.definitive_count = definitive_count
        self.comparison_count = comparison_count
        self.cap = cap
        super().__init__("reconcile side exceeds the comparison cap")


class ReconcileTimeoutError(Exception):
    """The comparison exceeded its DB time budget and was cancelled (narrow the scope)."""


@dataclass(slots=True)
class ReconcileItem:
    """One classified file, keyed by its path relative to both roots."""

    relpath: str
    classification: str
    definitive_size: int | None
    comparison_size: int | None
    definitive_hash: str | None
    comparison_hash: str | None


@dataclass(slots=True)
class ReconcileResult:
    """A reviewed cross-host comparison (read-only)."""

    definitive_volume_id: int
    definitive_root: str
    comparison_volume_id: int
    comparison_root: str
    counts: dict[str, int]
    considered: int  # total distinct relpaths across both sides
    items: list[ReconcileItem]
    truncated: bool


class ReconcileService:
    """Build a read-only, scope-bounded cross-host reconciliation (ADR-024)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _side(self, volume_id: int, root: str, scope: ScopeFilter | None) -> Subquery:
        """A subquery of ``(relpath, size, mtime, full_hash)`` for one root's files.

        ``relpath`` is the catalogue path with the ``root + "/"`` prefix stripped via ``substr``
        (DB-side; 1-based, so the offset is ``len(base) + 2``). Scope is enforced on the volume so
        an out-of-scope side yields no rows (fail-closed).
        """
        base = root.rstrip("/")
        like = escape_like(base) + "/%"
        offset = len(base) + 2  # 1-based substr start: skip ``base`` + the ``/``
        stmt: Select[tuple[str, int, float, str | None]] = (
            select(
                func.substr(FsEntryRow.path, offset).label("relpath"),
                FsEntryRow.size_logical.label("size"),
                FsEntryRow.mtime.label("mtime"),
                FsEntryRow.full_hash.label("full_hash"),
            )
            .join(Volume, Volume.id == FsEntryRow.volume_id)
            .where(
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
        return stmt.subquery()

    async def _count_side_capped(
        self, volume_id: int, root: str, scope: ScopeFilter | None, cap: int
    ) -> int:
        """Count present files under ``root``, **saturating at ``cap + 1``** (scan stops early).

        Used only to decide whether a side is too large to reconcile in one pass; the inner
        ``LIMIT`` bounds the work to ``cap + 1`` rows however huge the tree is. Same scope + system
        gate as :meth:`_side`, so an out-of-scope side counts as empty (fail-closed)."""
        base = root.rstrip("/")
        like = escape_like(base) + "/%"
        inner: Select[tuple[int]] = (
            select(literal(1))
            .select_from(FsEntryRow)
            .join(Volume, Volume.id == FsEntryRow.volume_id)
            .where(
                FsEntryRow.volume_id == volume_id,
                FsEntryRow.is_dir.is_(False),
                FsEntryRow.present.is_(True),
                FsEntryRow.path.like(like, escape=_LIKE_ESCAPE),
            )
        )
        if scope is not None:
            inner = scope.apply(
                inner,
                host_col=FsEntryRow.host_id,
                volume_col=FsEntryRow.volume_id,
                kind_col=Volume.kind,
            )
        capped = inner.limit(cap + 1).subquery()
        return int(
            (await self._session.execute(select(func.count()).select_from(capped))).scalar_one()
        )

    async def _apply_statement_timeout(self, seconds: float) -> None:
        """Best-effort per-transaction DB time cap (PostgreSQL ``SET LOCAL``); a no-op elsewhere."""
        bind = self._session.bind
        if bind is None or bind.dialect.name != "postgresql":
            return
        ms = int(seconds * 1000)
        try:
            await self._session.execute(text(f"SET LOCAL statement_timeout = {ms}"))
        except Exception:
            # A timeout we can't set just means no backstop here, not a failed request.
            _log.warning("could not set reconcile statement_timeout; comparison runs uncapped")

    async def compare(
        self,
        *,
        definitive_volume_id: int,
        definitive_root: str,
        comparison_volume_id: int,
        comparison_root: str,
        scope: ScopeFilter | None = None,
        max_side_entries: int = MAX_SIDE_ENTRIES,
        timeout_seconds: float = COMPARE_TIMEOUT_SECONDS,
    ) -> ReconcileResult:
        """Classify every file under the two roots by their shared relative path (read-only).

        Refuses (``ReconcileTooLargeError``) when either root holds more than ``max_side_entries``
        files — a whole-pool comparison is slow and rarely what's wanted (reconcile compares two
        copies of the SAME folder). A DB ``statement_timeout`` of ``timeout_seconds`` backstops an
        under-cap-but-pathological run, surfaced as ``ReconcileTimeoutError``.
        """
        def_count = await self._count_side_capped(
            definitive_volume_id, definitive_root, scope, max_side_entries
        )
        cmp_count = await self._count_side_capped(
            comparison_volume_id, comparison_root, scope, max_side_entries
        )
        if def_count > max_side_entries or cmp_count > max_side_entries:
            raise ReconcileTooLargeError(
                definitive_count=def_count, comparison_count=cmp_count, cap=max_side_entries
            )

        await self._apply_statement_timeout(timeout_seconds)
        try:
            return await self._compare_inner(
                definitive_volume_id, definitive_root, comparison_volume_id, comparison_root, scope
            )
        except OperationalError as exc:
            if _is_statement_timeout(exc):
                raise ReconcileTimeoutError() from exc
            raise

    async def _compare_inner(
        self,
        definitive_volume_id: int,
        definitive_root: str,
        comparison_volume_id: int,
        comparison_root: str,
        scope: ScopeFilter | None,
    ) -> ReconcileResult:
        left = self._side(definitive_volume_id, definitive_root, scope)
        right = self._side(comparison_volume_id, comparison_root, scope)

        # The content-class CASE for a matched (both-sides) relpath.
        both_hashed = and_(left.c.full_hash.isnot(None), right.c.full_hash.isnot(None))
        classify = case(
            (
                and_(
                    both_hashed,
                    left.c.full_hash == right.c.full_hash,
                    left.c.mtime == right.c.mtime,
                ),
                literal(IDENTICAL),
            ),
            (
                and_(both_hashed, left.c.full_hash == right.c.full_hash),
                literal(CONTENT_SAME_META_DIFF),
            ),
            (and_(both_hashed, left.c.full_hash != right.c.full_hash), literal(DIVERGED)),
            (left.c.size != right.c.size, literal(DIVERGED)),
            else_=literal(SIZE_MATCH_UNHASHED),
        )

        counts: dict[str, int] = dict.fromkeys(ALL_CLASSES, 0)

        # 1. matched relpaths, grouped by content class.
        matched_q = (
            select(classify.label("cls"), func.count().label("n"))
            .select_from(left.join(right, left.c.relpath == right.c.relpath))
            .group_by(classify)
        )
        for cls, n in (await self._session.execute(matched_q)).all():
            counts[str(cls)] = int(n)

        # 2. present-on-only-one-side (anti-joins; portable, no FULL OUTER JOIN).
        miss_comp = (
            select(func.count())
            .select_from(left.outerjoin(right, left.c.relpath == right.c.relpath))
            .where(right.c.relpath.is_(None))
        )
        miss_def = (
            select(func.count())
            .select_from(right.outerjoin(left, right.c.relpath == left.c.relpath))
            .where(left.c.relpath.is_(None))
        )
        counts[MISSING_ON_COMPARISON] = int((await self._session.execute(miss_comp)).scalar_one())
        counts[MISSING_ON_DEFINITIVE] = int((await self._session.execute(miss_def)).scalar_one())

        considered = sum(counts.values())
        items = await self._sample_items(left, right, classify)
        truncated = len(items) >= MAX_ITEMS

        return ReconcileResult(
            definitive_volume_id=definitive_volume_id,
            definitive_root=definitive_root.rstrip("/"),
            comparison_volume_id=comparison_volume_id,
            comparison_root=comparison_root.rstrip("/"),
            counts=counts,
            considered=considered,
            items=items,
            truncated=truncated,
        )

    async def _sample_items(
        self, left: Subquery, right: Subquery, classify: ColumnElement[str]
    ) -> list[ReconcileItem]:
        """A bounded preview of the actionable files (diverged + unhashed + missing each side)."""
        items: list[ReconcileItem] = []

        # Matched-but-flagged (diverged / size_match_unhashed).
        flagged_q = (
            select(
                left.c.relpath,
                classify.label("cls"),
                left.c.size,
                right.c.size,
                left.c.full_hash,
                right.c.full_hash,
            )
            .select_from(left.join(right, left.c.relpath == right.c.relpath))
            .where(classify.in_([DIVERGED, SIZE_MATCH_UNHASHED]))
            .order_by(left.c.relpath)
            .limit(MAX_ITEMS)
        )
        for rel, cls, lsz, rsz, lh, rh in (await self._session.execute(flagged_q)).all():
            items.append(ReconcileItem(str(rel), str(cls), lsz, rsz, lh, rh))

        # Missing on the comparison side.
        if len(items) < MAX_ITEMS:
            miss_q = (
                select(left.c.relpath, left.c.size, left.c.full_hash)
                .select_from(left.outerjoin(right, left.c.relpath == right.c.relpath))
                .where(right.c.relpath.is_(None))
                .order_by(left.c.relpath)
                .limit(MAX_ITEMS - len(items))
            )
            for rel, lsz, lh in (await self._session.execute(miss_q)).all():
                items.append(ReconcileItem(str(rel), MISSING_ON_COMPARISON, lsz, None, lh, None))

        # Missing on the definitive side.
        if len(items) < MAX_ITEMS:
            miss_q2 = (
                select(right.c.relpath, right.c.size, right.c.full_hash)
                .select_from(right.outerjoin(left, right.c.relpath == left.c.relpath))
                .where(left.c.relpath.is_(None))
                .order_by(right.c.relpath)
                .limit(MAX_ITEMS - len(items))
            )
            for rel, rsz, rh in (await self._session.execute(miss_q2)).all():
                items.append(ReconcileItem(str(rel), MISSING_ON_DEFINITIVE, None, rsz, None, rh))

        return items


def _is_statement_timeout(exc: OperationalError) -> bool:
    """Is this OperationalError a server-side statement_timeout cancellation? (asyncpg surfaces
    QueryCanceledError with SQLSTATE 57014; fall back to a message check for other drivers)."""
    sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
    if sqlstate == "57014":
        return True
    return "statement timeout" in str(exc).lower()
