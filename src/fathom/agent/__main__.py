"""Agent entry point: ``python -m fathom.agent`` (default scan) / ``... listen`` (ADR-025).

Reads its wiring from the environment (no secrets in argv), loads + validates the agent
config, and runs one of two modes:

* **scan** (default) — one ``scan → stage → push`` pass, then exit non-zero if any scope failed
  so a supervisor/cron can alert. Re-running is safe (staging is change-guarded, the server
  upsert idempotent).
* **listen** (``FATHOM_AGENT_MODE=listen`` or ``python -m fathom.agent listen``) — the always-on
  signed-job dispatch daemon (ADR-025): long-poll core → verify → execute → post results. It is
  fail-closed at startup (refuses to run without ``write_enabled`` + ``orchestrator_pubkey_ref`` +
  ``quarantine_dir``); scanning and listening are separate invocations so a scan-only host never
  carries the write path.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from fathom.adapters.base import PlatformAdapter
from fathom.agent.config import AgentConfig
from fathom.agent.loader import load_agent_config
from fathom.agent.runner import AgentRunSummary, run_agent
from fathom.logging import configure_logging, get_logger

_log = get_logger("fathom.agent.main")


def _default_staging() -> str:
    """Default staging-DB path, per OS (overridable via ``FATHOM_AGENT_STAGING``).

    POSIX: the FHS ``/var/lib`` location the Docker agent uses. Windows (ADR-027): under
    ``%PROGRAMDATA%`` — but the generated Windows bundle's launcher sets ``FATHOM_AGENT_STAGING``
    to the install dir explicitly, so this is only the bare-invocation fallback.
    """
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        return str(Path(base) / "Fathomline" / "staging.sqlite")
    return "/var/lib/fathom/staging.sqlite"


def _build_adapter(config: AgentConfig) -> PlatformAdapter | None:
    """Build the control-plane adapter from the agent config (ADD 04), or ``None`` if unconfigured.

    On a pure-ZFS/TrueNAS host this is what gives the full-bit resync guard a real pool-state
    signal (otherwise it fails closed with no ``/proc/mdstat`` and blocks full-bit forever,
    AR-0002 §5). The api_key_ref is resolved at runtime from the secret backend (ADR-010), never
    embedded. Only TrueNAS is wired here (the platform this gating matters for).
    """
    if config.adapter is None:
        return None
    from fathom.adapters.discovery import PlatformClass
    from fathom.adapters.truenas import TrueNASAdapter
    from fathom.backends.remote import env_or_docker_secret_provider

    if config.adapter.platform is PlatformClass.TRUENAS:
        return TrueNASAdapter(config.adapter, secret_provider=env_or_docker_secret_provider)
    _log.warning(
        "adapter platform not wired for the agent; resync guard stays signal-less",
        extra={"platform": config.adapter.platform.value},
    )
    return None


def _env_flag(name: str) -> bool:
    """Read a boolean env flag (``1``/``true``/``yes``/``on``, case-insensitive)."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _resolve_mode(argv: list[str]) -> str:
    """Resolve the run mode from argv (``listen``) or ``FATHOM_AGENT_MODE`` (default ``scan``)."""
    if len(argv) > 1 and argv[1]:
        return argv[1].strip().lower()
    return os.environ.get("FATHOM_AGENT_MODE", "scan").strip().lower()


def _run_listen(config_path: str) -> int:
    """Run the signed-job dispatch listener (ADR-025); fail-closed on a missing precondition."""
    from fathom.agent.actor.listen import ListenStartupError, run_listen
    from fathom.backends.remote import env_or_docker_secret_provider

    # A Scan Now job (ADR-025 + Scan Now) reuses the agent's scan staging DB + operator identity,
    # resolved from the same env the scan mode uses, so an immediate scan stages exactly where a
    # scheduled scan does.
    staging_path = os.environ.get("FATHOM_AGENT_STAGING", _default_staging())
    operator = os.environ.get("FATHOM_AGENT_OPERATOR", "fathom-agent")
    config = load_agent_config(config_path)
    try:
        asyncio.run(
            run_listen(
                config,
                secret_provider=env_or_docker_secret_provider,
                staging_path=staging_path,
                operator=operator,
            )
        )
    except ListenStartupError as exc:
        _log.error("listen mode refused to start", extra={"reason": str(exc)})
        return 2
    return 0


def _run_preview_serve(config_path: str) -> int:
    """Run the distributed-preview grant-serve daemon (ADR-014); fail-closed at startup."""
    from fathom.agent.preview_serve import PreviewServeStartupError, run_preview_serve
    from fathom.backends.remote import env_or_docker_secret_provider

    config = load_agent_config(config_path)
    try:
        asyncio.run(run_preview_serve(config, secret_provider=env_or_docker_secret_provider))
    except PreviewServeStartupError as exc:
        _log.error("preview-serve mode refused to start", extra={"reason": str(exc)})
        return 2
    return 0


def _run_browse_serve(config_path: str) -> int:
    """Run the live directory browse-serve daemon (ADR-034 Phase 2); fail-closed at startup."""
    from fathom.agent.browse_serve import BrowseServeStartupError, run_browse_serve
    from fathom.backends.remote import env_or_docker_secret_provider

    config = load_agent_config(config_path)
    try:
        asyncio.run(run_browse_serve(config, secret_provider=env_or_docker_secret_provider))
    except BrowseServeStartupError as exc:
        _log.error("browse-serve mode refused to start", extra={"reason": str(exc)})
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run an agent pass (or the listen / preview-serve / browse-serve daemon); return exit code."""
    configure_logging()
    argv = argv if argv is not None else sys.argv
    config_path = os.environ.get("FATHOM_AGENT_CONFIG")
    if not config_path:
        _log.error("FATHOM_AGENT_CONFIG is required (path to the agent config file)")
        return 2

    mode = _resolve_mode(argv)
    if mode == "listen":
        return _run_listen(config_path)
    if mode == "preview-serve":
        return _run_preview_serve(config_path)
    if mode == "browse-serve":
        return _run_browse_serve(config_path)
    if mode != "scan":
        _log.error(
            "unknown agent mode (expected 'scan', 'listen', 'preview-serve', or 'browse-serve')",
            extra={"mode": mode},
        )
        return 2

    staging_path = os.environ.get("FATHOM_AGENT_STAGING", _default_staging())
    operator = os.environ.get("FATHOM_AGENT_OPERATOR", "fathom-agent")
    # A scheduled "refresh" run sets this to skip the incremental feed and re-walk fully, which is
    # what re-runs full-bit on a change-feed host so its dedup hashes track changed content
    # (full-bit only runs on a full walk). Cheap on the unchanged majority (change-guarded upsert).
    force_full_walk = _env_flag("FATHOM_AGENT_FORCE_FULL_WALK")

    config = load_agent_config(config_path)
    # ADR-033 (#10): pull the operator's per-host config override and apply it fail-safe. Identity /
    # transport / secret fields are never overridable; an invalid or absent override keeps the local
    # config. Done before the scan so the run uses (and then reports) the effective config.
    config = _apply_config_override(config)
    # ADR-036: ask the core for a scan lease before walking. If the coordinator DEFERS (a heavy
    # scan is already running), skip this run cleanly — the next scheduled run retries. Fail-open:
    # any error (no coordinator / core down) proceeds with the scan, so coordination never blocks.
    if _scan_deferred(config):
        return 0
    adapter = _build_adapter(config)
    summary = asyncio.run(
        run_agent(
            config,
            staging_path=staging_path,
            operator=operator,
            adapter=adapter,
            adapter_pool=config.adapter_pool,
            force_full_walk=force_full_walk,
        )
    )
    _report_run(config, summary)
    if summary.failed_scopes:
        _log.error("agent run had failed scopes", extra={"failed": summary.failed_scopes})
        return 1
    return 0


def _apply_config_override(config: AgentConfig) -> AgentConfig:
    """Fetch + apply the operator's per-host config override (ADR-033 #10), fail-safe.

    Best-effort + fail-closed-to-local: any fetch/transport error or an override that fails the
    agent's own re-validation logs and returns the unchanged local ``config`` — a bad or
    unreachable override never breaks scanning. Only the safe overridable fields are honoured.
    """
    from fathom.agent.runner import fetch_config_override

    try:
        override = asyncio.run(fetch_config_override(config))
    except Exception as exc:  # transport/HTTP — keep local config
        _log.warning("config override fetch failed; using local config", extra={"error": str(exc)})
        return config
    if not override:
        return config
    try:
        merged = config.with_override(override)
    except Exception as exc:  # re-validation failed — keep local config (fail-safe)
        _log.warning(
            "operator config override invalid; using local config", extra={"error": str(exc)}
        )
        return config
    _log.info("applied operator config override", extra={"fields": sorted(override.keys())})
    return merged


def _scan_deferred(config: AgentConfig) -> bool:
    """Ask the core for a scan lease; return True iff it DEFERRED this run (ADR-036), else False.

    Best-effort + fail-open: any transport/HTTP error (no coordinator, core down, old core without
    the endpoint) returns False so the scan proceeds — coordination must never block scanning. Only
    an explicit ``granted: false`` defers, and the advisory (reason + retry-after) is logged.
    """
    from fathom.agent.runner import request_scan_lease

    try:
        decision = asyncio.run(request_scan_lease(config))
    except Exception as exc:  # transport/HTTP — proceed with the scan (fail-open)
        _log.warning("scan-lease check failed; scanning anyway", extra={"error": str(exc)})
        return False
    if decision.get("granted", True):
        return False
    _log.warning(
        "scan deferred by coordinator; skipping this run",
        extra={
            "reason": decision.get("reason"),
            "retry_after_seconds": decision.get("retry_after_seconds"),
            "blocking_host": decision.get("blocking_host"),
        },
    )
    return True


def _report_run(config: AgentConfig, summary: AgentRunSummary) -> None:
    """Best-effort end-of-run report to core (observability). Never fails the scan.

    A reporting hiccup (core down, network blip) must not turn an otherwise-good scan into a
    non-zero exit, so failures are logged and swallowed — the scan's own outcome stands.
    """
    from fathom import __version__
    from fathom.agent.runner import build_run_report, report_run

    started = summary.started_at or datetime.now(tz=UTC)
    finished = summary.finished_at or datetime.now(tz=UTC)
    try:
        body = build_run_report(
            summary, started_at=started, finished_at=finished, agent_version=__version__
        )
        # ADR-033 (#9): report the EFFECTIVE config this run used (post-override), so the Agents UI
        # shows what the agent is actually configured to scan + how it's throttled.
        body["reported_config"] = config.reportable()
        asyncio.run(report_run(config, body))
    except Exception as exc:  # observability is best-effort; never fail a good scan on it
        _log.warning("run report failed (non-fatal)", extra={"error": str(exc)})


if __name__ == "__main__":
    raise SystemExit(main())
