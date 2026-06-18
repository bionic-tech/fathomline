"""The actor — remediation ONLY, a separate process under a separate OS user (ADD 02).

Read != write at the OS level: the reader users have no write rights; only ``strata-actor``
owns the quarantine directory and may mutate approved paths. This package is library code,
default-disabled (``write_enabled=False``), and not wired to any remotely-reachable execute
endpoint in v1 (AR-0003). It exists so the safety guards can be built and regression-tested
before any execute path is ever enabled (AR-0006, ADR-011).
"""

from fathom.agent.actor.dispatch import ActorDispatcher, JobResult, plan_from_job
from fathom.agent.actor.executor import (
    BlastRadiusError,
    ExecOutcome,
    ExecResult,
    Executor,
    RemediationDisabledError,
)
from fathom.agent.actor.listener import SignedJobListener
from fathom.agent.actor.planner import VerifyReport, dry_run_verify

__all__ = [
    "ActorDispatcher",
    "BlastRadiusError",
    "ExecOutcome",
    "ExecResult",
    "Executor",
    "JobResult",
    "RemediationDisabledError",
    "SignedJobListener",
    "VerifyReport",
    "dry_run_verify",
    "plan_from_job",
]
