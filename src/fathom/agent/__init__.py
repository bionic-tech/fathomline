"""On-host agent runtime (ADD 02).

The agent is the only component that touches a filesystem. Stage 1 ships the read side:
fail-fast config, the local SQLite staging queue, and the throttled metadata walker with
its adaptive supervisor. The actor (write/remediation) process is a separate user and a
separate, later-built and harder-reviewed surface (ADD 02 §Mode 3, AR-0006) — it is
absent from this package by design.
"""
