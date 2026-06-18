"""Tests for the hash-chained audit log (AR-0012)."""

from __future__ import annotations

import dataclasses

from fathom.core.audit import AuditChain, verify_chain


def _chain() -> tuple[AuditChain, list]:
    sink: list = []
    return AuditChain(sink=sink.append), sink


def test_chain_verifies() -> None:
    chain, sink = _chain()
    for i in range(3):
        chain.append(
            actor="strata-actor",
            action="quarantine",
            target=f"/v/f{i}",
            before_state={"inode": i, "size": 10},
            result="quarantined",
        )
    assert len(sink) == 3
    assert verify_chain(sink) is True


def test_links_chain_to_prev() -> None:
    chain, _ = _chain()
    a = chain.append(actor="x", action="a", target="/t", before_state={}, result="ok")
    b = chain.append(actor="x", action="a", target="/t", before_state={}, result="ok")
    assert b.prev_hash == a.row_hash


def test_tamper_breaks_chain() -> None:
    chain, sink = _chain()
    for i in range(3):
        chain.append(actor="x", action="a", target=f"/t{i}", before_state={}, result="ok")
    # Tamper with the middle record's payload, keeping its stored hash.
    sink[1] = dataclasses.replace(sink[1], result="forged")
    assert verify_chain(sink) is False


def test_deletion_breaks_chain() -> None:
    chain, sink = _chain()
    for i in range(3):
        chain.append(actor="x", action="a", target=f"/t{i}", before_state={}, result="ok")
    del sink[1]  # drop a record → prev_hash linkage breaks
    assert verify_chain(sink) is False
