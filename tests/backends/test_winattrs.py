"""Windows attribute classification (ADR-027 W1) — pure logic, runs on every platform."""

from __future__ import annotations

import pytest

from fathom.backends.winattrs import (
    ATTR_OFFLINE,
    ATTR_RECALL_ON_DATA_ACCESS,
    ATTR_RECALL_ON_OPEN,
    ATTR_REPARSE_POINT,
    classify_attributes,
)


def test_plain_entry_descends_and_hashes() -> None:
    cls = classify_attributes(0)  # also what every POSIX stat classifies as
    assert not cls.is_reparse and not cls.is_placeholder
    assert cls.descend_ok and cls.hash_ok


def test_reparse_point_is_never_descended_or_hashed() -> None:
    cls = classify_attributes(ATTR_REPARSE_POINT)
    assert cls.is_reparse
    assert not cls.descend_ok  # junctions are the Windows traversal-escape primitive
    assert not cls.hash_ok


@pytest.mark.parametrize(
    "attrs",
    [ATTR_OFFLINE, ATTR_RECALL_ON_OPEN, ATTR_RECALL_ON_DATA_ACCESS],
)
def test_placeholder_variants_are_never_hashed(attrs: int) -> None:
    # Opening content would hydrate the file — metadata only, never hash (never download).
    cls = classify_attributes(attrs)
    assert cls.is_placeholder
    assert not cls.hash_ok
    assert cls.descend_ok  # placeholder without reparse: listing children is safe


def test_onedrive_style_reparse_placeholder_combination() -> None:
    # Real cloud placeholders typically carry BOTH bits: reparse anchor + recall-on-access.
    cls = classify_attributes(ATTR_REPARSE_POINT | ATTR_RECALL_ON_DATA_ACCESS)
    assert cls.is_reparse and cls.is_placeholder
    assert not cls.descend_ok and not cls.hash_ok


def test_unrelated_attribute_bits_are_ignored() -> None:
    readonly_hidden = 0x1 | 0x2  # FILE_ATTRIBUTE_READONLY | HIDDEN
    cls = classify_attributes(readonly_hidden)
    assert cls.descend_ok and cls.hash_ok
