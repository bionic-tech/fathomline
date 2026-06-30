"""Fathom — multi-host disk-estate analysis platform.

This package is laid out as a modular monolith (standards/18 §6). Stage 1
(Foundations) ships the read-only agent core: the ``StorageBackend`` protocol,
fail-fast configuration models, the local SQLite staging queue, and the throttled
metadata walker with its adaptive supervisor. The transport, ingest API, dedup, and
remediation surfaces are deliberately absent until their own build stages and review
gates clear (see docs/00-documentation-suite-plan.md "Build order").
"""

__version__ = "0.2.0"
