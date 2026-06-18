"""Scope value object + ScopeFilter (ADD 13 §4).

A principal's effective scope for a capability is the **union** of the scopes of the grants
whose role confers that capability. Scope is one of:

- **global** — the whole estate (``is_global``);
- a set of **host** ids (host-level scope);
- a set of **(host, volume)** ids (volume-level / finest scope per owner ruling).

The filter is server-authoritative: it is built only from the assignment store, never from
client input (ADD 13 §4). It is applied to read queries (you only see in-scope
hosts/volumes) via :meth:`ScopeFilter.apply`, and write targets are checked with
:meth:`ScopeFilter.check_target` (out-of-scope → 403).

Root/system volumes (``volume.kind == 'system'``) are gated here too: they are metadata-only
at the human-RBAC layer (AR-011, mirroring the OS strata-rootreader ``CAP_DAC_READ_SEARCH``
control) and are excluded unless the grant covers them explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeVar

from fastapi import HTTPException, status
from sqlalchemy import Select, false, or_
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql.elements import ColumnElement

from fathom.auth.principal import Capability, Grant, role_has

_SelectT = TypeVar("_SelectT", bound=Select)  # type: ignore[type-arg]
# A scope-constrainable column: a raw ColumnElement or a mapped ORM attribute (the SQLAlchemy
# mypy plugin types mapped columns as InstrumentedAttribute, which it does not unify with
# ColumnElement, so both are accepted explicitly).
_ScopeColumn = ColumnElement[int] | InstrumentedAttribute[int]
# A string-valued column (e.g. ``Volume.kind``) constrained by the system-volume gate.
_KindColumn = ColumnElement[str] | InstrumentedAttribute[str]

SYSTEM_VOLUME_KIND = "system"
DATA_VOLUME_KIND = "data"


@dataclass(slots=True)
class ScopeFilter:
    """A resolved, server-authoritative scope for one capability (ADD 13 §4).

    ``is_global`` short-circuits all checks. Otherwise ``host_ids`` and ``volume_ids`` are
    the in-scope sets; an empty, non-global filter denies everything (fail-closed).
    """

    is_global: bool = False
    host_ids: frozenset[int] = field(default_factory=frozenset)
    volume_ids: frozenset[int] = field(default_factory=frozenset)

    @classmethod
    def from_grants(cls, grants: tuple[Grant, ...], capability: Capability) -> ScopeFilter:
        """Build the union scope over the grants whose role confers ``capability``."""
        relevant = [g for g in grants if role_has(g.role, capability)]
        if not relevant:
            # No grant confers the capability → empty, non-global → denies all (fail-closed).
            return cls(is_global=False)
        if any(g.scope_kind == "global" for g in relevant):
            return cls(is_global=True)
        host_ids = {g.host_id for g in relevant if g.scope_kind == "host" and g.host_id is not None}
        volume_ids = {
            g.volume_id for g in relevant if g.scope_kind == "volume" and g.volume_id is not None
        }
        return cls(
            is_global=False,
            host_ids=frozenset(host_ids),
            volume_ids=frozenset(volume_ids),
        )

    @property
    def is_empty(self) -> bool:
        """True when nothing is in scope (non-global with no host/volume) → deny-all."""
        return not self.is_global and not self.host_ids and not self.volume_ids

    def covers_system_volume(self, volume_id: int | None) -> bool:
        """Whether the grant explicitly covers ``volume_id`` as a (system) volume (AR-011).

        A system volume (``Volume.kind == SYSTEM_VOLUME_KIND``) is metadata-only at the
        human-RBAC layer and is reachable only when the grant names it explicitly: a global
        grant (the whole estate) or a **volume-scoped** grant on that exact volume id. A
        host-scoped grant — even on the system volume's host — does **not** confer system-volume
        access (mirrors the OS strata-rootreader ``CAP_DAC_READ_SEARCH`` gate, AR-011).
        """
        if self.is_global:
            return True
        return volume_id is not None and volume_id in self.volume_ids

    def apply(
        self,
        stmt: _SelectT,
        *,
        host_col: _ScopeColumn | None = None,
        volume_col: _ScopeColumn | None = None,
        kind_col: _KindColumn | None = None,
    ) -> _SelectT:
        """Push in-scope ``host_id``/``volume_id`` predicates into ``stmt``.

        ``host_col``/``volume_col`` are the columns to constrain. Global scope adds nothing.
        An empty non-global scope adds an always-false predicate so the query returns nothing
        (fail-closed; never leak out-of-scope rows).

        When ``kind_col`` (e.g. ``Volume.kind``) is supplied, a system-volume gate is ANDed in
        (AR-011): a non-global principal sees a system volume only when a volume-scoped grant
        names it explicitly. Concretely the row must be ``kind != SYSTEM_VOLUME_KIND`` **or** an
        explicitly in-scope ``volume_id`` (so a system volume the grant names by id stays
        visible). Without ``kind_col`` the gate is not applied — callers query a table that
        carries the volume kind (``Volume``) thread it; member/path tables that cannot do not.
        """
        if self.is_global:
            return stmt
        predicates: list[ColumnElement[bool]] = []
        if host_col is not None and self.host_ids:
            predicates.append(host_col.in_(self.host_ids))
        if volume_col is not None and self.volume_ids:
            predicates.append(volume_col.in_(self.volume_ids))
        if not predicates:
            # Fail-closed: in-scope sets do not match any available column → return nothing.
            return stmt.where(false())
        # OR across host/volume membership: a row is visible if it matches any in-scope set.
        stmt = stmt.where(or_(*predicates))
        if kind_col is not None:
            # System-volume gate (AR-011): exclude kind=='system' rows unless the grant names
            # the volume id explicitly. A data volume is always allowed; a system volume only
            # when its id is in the volume-scoped set.
            system_ok: ColumnElement[bool] = kind_col != SYSTEM_VOLUME_KIND
            if volume_col is not None and self.volume_ids:
                system_ok = or_(system_ok, volume_col.in_(self.volume_ids))
            stmt = stmt.where(system_ok)
        return stmt

    def check_target(
        self,
        *,
        host_id: int,
        volume_id: int | None = None,
        volume_kind: str | None = None,
    ) -> None:
        """Authorise a write/preview/drill target; raise 403 if out of scope (ADD 13 §4).

        A volume-scoped grant matches when ``volume_id`` is in scope; a host-scoped grant
        matches when ``host_id`` is in scope. Global passes unconditionally.

        When ``volume_kind`` is supplied and the target is a **system** volume
        (``volume_kind == SYSTEM_VOLUME_KIND``), the target is gated by AR-011: a non-global
        principal may reach it only via a volume-scoped grant that names this exact volume id —
        a host-scoped grant (even on the right host) is rejected ``403`` for a system volume.
        """
        if self.is_global:
            return
        if volume_kind == SYSTEM_VOLUME_KIND and not self.covers_system_volume(volume_id):
            # System volume reachable only via an explicit volume grant naming it (AR-011).
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="system volume out of scope",
            )
        if volume_id is not None and volume_id in self.volume_ids:
            return
        if host_id in self.host_ids:
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="target out of scope",
        )
