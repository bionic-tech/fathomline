"""Windows file-attribute semantics for the W1 walker (ADR-027 §phase W1).

Pure classification of ``st_file_attributes`` bits into walk decisions — no I/O, no
platform dependency (the constants are plain ints), so the rules are unit-tested on every
platform while only a real Windows host ever produces non-zero attributes.

Two properties matter to the walker:

- **Reparse points** (symlinks, junctions, mount points, cloud-placeholder anchors) are
  reported but **never descended into** — the skip-don't-follow rule. Junctions are the
  Windows traversal-escape primitive (the ``..``/symlink analogue), and a reparse directory
  can alias another volume entirely.
- **Cloud placeholders** (OneDrive et al. dehydrated files) are catalogued from metadata
  but their content is **never opened** — opening is what triggers hydration, and a scan
  that silently downloads a terabyte of "files on demand" is a catastrophe, not a feature.
"""

from __future__ import annotations

import os
import stat as stat_mod
from dataclasses import dataclass

# Defined in the stat module on every platform (values are Win32 constants).
ATTR_REPARSE_POINT: int = stat_mod.FILE_ATTRIBUTE_REPARSE_POINT  # 0x0000_0400
ATTR_OFFLINE: int = stat_mod.FILE_ATTRIBUTE_OFFLINE  # 0x0000_1000
# Newer Win32 attributes not yet mirrored in CPython's stat module: set on cloud
# placeholders whose content is not local ("recall" = hydrate-on-touch).
ATTR_RECALL_ON_OPEN: int = 0x0004_0000
ATTR_RECALL_ON_DATA_ACCESS: int = 0x0040_0000

_PLACEHOLDER_MASK = ATTR_OFFLINE | ATTR_RECALL_ON_OPEN | ATTR_RECALL_ON_DATA_ACCESS


@dataclass(frozen=True, slots=True)
class WindowsEntryClass:
    """The walk-relevant classification of one Windows directory entry."""

    is_reparse: bool
    is_placeholder: bool

    @property
    def descend_ok(self) -> bool:
        """Directories may be walked into only if they are not reparse points."""
        return not self.is_reparse

    @property
    def hash_ok(self) -> bool:
        """Content may be opened (W2) only for plain, fully-local entries."""
        return not (self.is_reparse or self.is_placeholder)


def classify_attributes(file_attributes: int) -> WindowsEntryClass:
    """Classify raw ``st_file_attributes`` bits (0 — e.g. on POSIX — is a plain entry)."""
    return WindowsEntryClass(
        is_reparse=bool(file_attributes & ATTR_REPARSE_POINT),
        is_placeholder=bool(file_attributes & _PLACEHOLDER_MASK),
    )


def entry_attributes(st: os.stat_result) -> int:
    """Return ``st_file_attributes``, or 0 where the platform has none (POSIX)."""
    return getattr(st, "st_file_attributes", 0)
