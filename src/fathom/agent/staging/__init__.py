"""Local agent staging — embedded SQLite (WAL), resumable delta queue (ADD 02 §7).

A network blip never loses a scan: entries are staged locally and pushed as idempotent
deltas. The staging DB is disposable — re-derived by a re-scan (ADD 09 §7) — so it holds
no durable system-of-record data.
"""

from fathom.agent.staging.store import StagingStore

__all__ = ["StagingStore"]
