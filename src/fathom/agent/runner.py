"""Agent runner — the end-to-end metadata scan → stage → push loop (ADD 02, build step 1).

Wires the read-only :class:`PosixBackend`, the throttling :class:`LoadSupervisor`, the
:class:`MetadataScanner`, the resumable SQLite :class:`StagingStore`, and the CA-pinned
mTLS :class:`PushClient` into a single one-shot run: scan every ``scan_scope`` root into
staging, then drain staging to the core ingest endpoint. A failure on one scope is logged
and skipped — one unreadable mount must never abort the whole run. The drain step is
injectable so it can be unit-tested without certificates or a live server.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from fathom.adapters.base import PlatformAdapter
from fathom.adapters.resync import adapter_resync_provider
from fathom.agent.config import AgentConfig
from fathom.agent.reader.feed import ChangeFeed, RestatFeed
from fathom.agent.reader.fullbit import FullBitBlocked, FullBitScanner
from fathom.agent.reader.hasher import BackendHasher
from fathom.agent.reader.incremental import IncrementalScanner
from fathom.agent.reader.supervisor import LoadSupervisor
from fathom.agent.reader.walker import AcknowledgementRequired, MetadataScanner, WarningAck
from fathom.agent.staging.store import StagingStore
from fathom.agent.transport.push import PushClient, mtls_client
from fathom.backends.base import FullBitUnsupportedError, StorageBackend, VolumeInfo
from fathom.backends.registry import BackendRegistry, NoBackendError, build_default_registry
from fathom.backends.remote import SecretProvider
from fathom.core.dedup import Candidate
from fathom.logging import get_logger

_log = get_logger("fathom.agent.runner")

DrainFn = Callable[[StagingStore], Awaitable[int]]
# Returns the number of volumes the server recomputed rollups for (0 when nothing changed).
FinalizeFn = Callable[[], Awaitable[int]]

# Resolves the incremental change feed for an already-baselined scope (ADR-006). Returns a
# :class:`ChangeFeed` to use instead of a full re-walk, or ``None`` when no feed can run for this
# scope — in which case the runner conservatively falls back to a full walk rather than risk
# missing changes. The default resolver is :func:`_default_feed_for`; tests inject a fake.
FeedFactory = Callable[
    [StorageBackend, VolumeInfo, str, StagingStore, AgentConfig], ChangeFeed | None
]

FINALIZE_PATH = "/api/v1/agents/finalize"
# The post-drain finalize recomputes subtree rollups AND rebuilds the estate-wide dedup groups
# server-side — a bulk pass that takes minutes on a large hashed estate, not the 30s default ingest
# timeout (which made finalize "fail" while the server kept working). Give it a generous ceiling;
# it runs once per scan and is best-effort, so a slow finalize never blocks an otherwise-good run.
FINALIZE_TIMEOUT_SECONDS = 900.0

# The drain pushes ingest batches (fast) AND the removals batch. On a large estate the server-side
# removals reconciliation (marking absent rows not-present, ADR-006) is a bulk pass that can exceed
# the 30s default ingest timeout on a multi-million-row volume — the SAME "agent gives up while the
# server keeps working" failure that bit finalize. Give each drain POST a generous read ceiling
# (normal chunks still return in <1s; only the heavy removals chunk uses the headroom).
DRAIN_TIMEOUT_SECONDS = 600.0

RUNS_PATH = "/api/v1/agents/runs"


def build_run_report(
    summary: AgentRunSummary,
    *,
    started_at: datetime,
    finished_at: datetime,
    agent_version: str | None = None,
) -> dict[str, object]:
    """Build the JSON body for the end-of-run report (matches ``schemas.AgentRunReport``).

    Pure + serializable so the agent's reporting is testable without a server. The server
    re-derives the aggregate outcome from ``scopes`` — this only describes the host's own scopes.
    """
    return {
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "pushed": summary.pushed,
        "finalized": summary.finalized,
        "agent_version": agent_version,
        "scopes": [
            {
                "root": s.root,
                "entries_seen": s.entries_seen,
                "rows_changed": s.rows_changed,
                "error": s.error,
                "fullbit_hashed": s.fullbit_hashed,
                "fullbit_error": s.fullbit_error,
            }
            for s in summary.scopes
        ],
    }


async def report_run(config: AgentConfig, body: dict[str, object]) -> None:
    """POST the end-of-run report over the same CA-pinned mTLS channel as ingest (observability).

    The host is the verified cert fingerprint, never the body (same boundary as ingest/finalize).
    Caller treats this as best-effort: run-reporting must never destabilise an otherwise-good scan.
    """
    async with mtls_client(config) as client:
        resp = await client.post(RUNS_PATH, json=body)
        resp.raise_for_status()


CONFIG_PATH = "/api/v1/agents/config"


async def fetch_config_override(config: AgentConfig) -> dict[str, object] | None:
    """GET this host's operator-set config override (ADR-033 #10) over the mTLS channel.

    Returns the override dict, or ``None`` when there is none (HTTP 204). The host is the verified
    cert fingerprint (same boundary as ingest). Raises on transport/HTTP errors — the caller treats
    it as best-effort and keeps its local config (fail-safe), so a core hiccup never blocks a scan.
    """
    async with mtls_client(config) as client:
        resp = await client.get(CONFIG_PATH)
        if resp.status_code == 204:
            return None
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else None


SCAN_LEASE_PATH = "/api/v1/agents/scan-lease"


async def request_scan_lease(config: AgentConfig) -> dict[str, object]:
    """Ask the core for a pre-scan lease (ADR-036) over the mTLS channel; return its decision.

    The host is the verified cert fingerprint (same boundary as ingest). Returns the coordinator's
    JSON verdict (``granted``/``status``/``reason``/``retry_after_seconds``/``blocking_host``).
    Raises on transport/HTTP errors — the caller treats it as best-effort and scans anyway
    (fail-open: a missing/old/unreachable coordinator never blocks a scan).
    """
    async with mtls_client(config) as client:
        resp = await client.post(SCAN_LEASE_PATH)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else {}


def _default_feed_for(
    backend: StorageBackend,
    volume: VolumeInfo,
    root: str,
    staging: StagingStore,
    config: AgentConfig,
) -> ChangeFeed | None:
    """Pick the incremental change feed for an already-baselined ``root`` (ADR-006).

    * **ZFS** — the cheapest feed is ``zfs diff`` between successive snapshots, but that needs
      per-cycle snapshot/bookmark management the agent does not yet take. Until that lands, a ZFS
      dataset has *no runnable feed here*, so this returns ``None`` and the caller falls back to a
      full walk — correct and conservative (never miss a change), the explicit ADR-006 fallback for
      "the feed cannot run (no snapshots)".
    * **Everything else** — the portable :class:`RestatFeed`: it re-``stat``\\ s the tree and diffs
      against the prior cycle's ``{(dev, inode): (mtime, path)}`` baseline (loaded from the
      persisted staged rows) to emit only created/modified/deleted entries. Both the baseline and
      deletions key on ``(dev, inode)`` — matching the catalogue identity — so colliding inodes on
      different ZFS child datasets of a ``cross_mounts`` volume don't collapse.
    """
    if volume.fs_type == "zfs":
        # No snapshot/bookmark plumbing yet → cannot run zfs diff safely; full-walk fallback.
        _log.info(
            "no incremental feed for zfs scope yet (needs snapshots); full walk",
            extra={"root": root, "volume": volume.mountpoint},
        )
        return None
    baseline = staging.load_baseline(host_id=config.host_id, volume_id=volume.mountpoint)
    return RestatFeed(backend, baseline, exclude=config.exclude_scope)


@dataclass(slots=True)
class ScopeOutcome:
    """Result of scanning one ``scan_scope`` root."""

    root: str
    entries_seen: int
    rows_changed: int
    error: str | None = None
    # Set when this scope was also full-bit-hashed (within fullbit_scope). ``fullbit_error``
    # records why a requested full-bit pass was refused/skipped (ack/resync/unsupported) without
    # failing the metadata scan — the two are independent (fullbit-dedup).
    fullbit_hashed: int = 0
    fullbit_error: str | None = None


@dataclass(slots=True)
class AgentRunSummary:
    """Aggregate outcome of an agent run."""

    host_id: str
    scopes: list[ScopeOutcome]
    pushed: int
    # Volumes the server recomputed rollups for in the post-drain finalize (ADD 09 §8). ``None``
    # when finalize was skipped/failed; failure never aborts the run (the deltas are already
    # ingested — only the rollups lag).
    finalized: int | None = None
    # Wall-clock bounds of the run (observability). Default None keeps any direct construction
    # behaviour-preserving; run_agent always sets them.
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def entries_seen(self) -> int:
        return sum(s.entries_seen for s in self.scopes)

    @property
    def failed_scopes(self) -> list[str]:
        return [s.root for s in self.scopes if s.error is not None]


async def _mtls_drain(config: AgentConfig, staging: StagingStore, *, push_chunk: int) -> int:
    async with mtls_client(config, timeout=DRAIN_TIMEOUT_SECONDS) as client:
        return await PushClient(client, chunk_size=push_chunk).drain(staging)


async def _mtls_finalize(config: AgentConfig) -> int:
    """POST the post-drain rollup finalize over the same CA-pinned mTLS channel as ingest.

    The server recomputes ``subtree_rollup`` for this host's freshly-ingested volumes (the host is
    the verified cert fingerprint, never the body — same boundary as ingest). Returns the number
    of volumes recomputed.
    """
    async with mtls_client(config, timeout=FINALIZE_TIMEOUT_SECONDS) as client:
        resp = await client.post(FINALIZE_PATH)
        resp.raise_for_status()
        body = resp.json()
        return len(body.get("volume_ids", []))


def _scanner_for(
    backend: StorageBackend,
    staging: StagingStore,
    supervisor: LoadSupervisor,
    config: AgentConfig,
    *,
    batch_size: int,
) -> MetadataScanner:
    """Build a per-scope :class:`MetadataScanner` bound to the resolved backend.

    ``cross_mounts=True`` turns ``one_filesystem`` off so a ZFS pool-root walk descends into child
    datasets (each its own ``st_dev``); it is inert for remote backends, which have no nested
    mounts to cross (storage-backends §dataset boundaries).
    """
    return MetadataScanner(
        backend=backend,
        staging=staging,
        supervisor=supervisor,
        host_id=config.host_id,
        batch_size=batch_size,
        one_filesystem=not config.cross_mounts,
        exclude=config.exclude_scope,
    )


def _fullbit_ack(operator: str, root: str, volume: VolumeInfo) -> WarningAck:
    """Build the full-bit impact ack naming the backing device class (non-impact contract).

    The message names the transport + RAID role so the persisted ack records *what* the operator
    accepted (e.g. "USB RAID5"); the scanner re-checks the ack's ``mode == 'fullbit'`` (ADD 02).
    """
    device_class = volume.transport
    if volume.raid_role:
        device_class = f"{volume.transport} {volume.raid_role}"
    return WarningAck(
        operator=operator,
        acknowledged_at=datetime.now(tz=UTC),
        target=f"{root} (backing device class: {device_class})",
        mode="fullbit",
    )


async def _run_fullbit(
    *,
    backend: StorageBackend,
    staging: StagingStore,
    supervisor: LoadSupervisor,
    config: AgentConfig,
    operator: str,
    root: str,
    volume: VolumeInfo,
    outcome: ScopeOutcome,
) -> None:
    """Run a full-bit pass over ``root``'s staged candidates, recording the outcome.

    The full-bit pass is gated by the scanner itself (ack + resync block + load pause) and only
    ever runs on this owning host's local backend — ``open_for_hash`` raising
    :class:`FullBitUnsupportedError` is the hard refusal for a remote (SMB/SFTP) backend, never a
    config flag (security_constraints: full-bit never over SMB/SFTP/NFS). Failures here are
    recorded on the scope but never abort the metadata result or the push.
    """
    # Stream candidates one size-group at a time so peak memory is a single same-size group, not
    # the whole scope. Materialising every candidate (millions on a large NAS) OOM-killed the
    # 1 GiB scanner before any hash was staged (ADR-025 scan-fix). The collision-size set is small
    # (only sizes shared by >=2 files — a unique size is never opened), and each per-size fetch is
    # bounded; reads run off the event loop via ``to_thread``.
    sizes = await asyncio.to_thread(
        staging.collision_sizes,
        host_id=config.host_id,
        volume_id=volume.mountpoint,
        scope_prefix=root,
    )

    async def _size_groups() -> AsyncIterator[Sequence[Candidate]]:
        for size in sizes:
            rows = await asyncio.to_thread(
                staging.candidates_of_size,
                host_id=config.host_id,
                volume_id=volume.mountpoint,
                scope_prefix=root,
                size=size,
            )
            yield [
                Candidate(
                    id=row["inode"], path=row["path"], size=row["size_logical"], dev=row["dev"]
                )
                for row in rows
            ]

    scanner = FullBitScanner(
        backend=backend,
        hasher=BackendHasher(backend),
        staging=staging,
        supervisor=supervisor,
        host_id=config.host_id,
        hash_concurrency=config.throttle.hash_concurrency,
    )
    ack = _fullbit_ack(operator, root, volume)
    try:
        result = await scanner.scan_grouped(
            root, _size_groups(), volume_id=volume.mountpoint, warning_ack=ack, volume=volume
        )
    except FullBitBlocked as exc:
        outcome.fullbit_error = str(exc)
        _log.warning("full-bit blocked", extra={"root": root, "error": str(exc)})
        return
    except (AcknowledgementRequired, FullBitUnsupportedError, OSError) as exc:
        outcome.fullbit_error = str(exc)
        _log.error("full-bit pass failed", extra={"root": root, "error": str(exc)})
        return
    outcome.fullbit_hashed = result.full_hashed


async def _scan_one_scope(
    *,
    backend: StorageBackend,
    staging: StagingStore,
    supervisor: LoadSupervisor,
    config: AgentConfig,
    operator: str,
    root: str,
    batch_size: int,
    feed_factory: FeedFactory,
    force_full_walk: bool = False,
) -> tuple[ScopeOutcome, VolumeInfo | None]:
    """Scan one scope, full-walking the first time and light-touch incremental thereafter.

    The first scan of a ``(host, volume)`` is the warned full walk (as before); once a baseline
    metadata run has finished, subsequent cycles ask ``feed_factory`` for a :class:`ChangeFeed` and
    stage only deltas + deletions (ADR-006, "after first index switch to light-touch incremental").
    If no feed can run for this scope (``feed_factory`` → ``None``: e.g. a ZFS dataset with no
    snapshot plumbing, or a permission/feed error), it conservatively falls back to a full walk
    rather than risk missing a change.

    ``force_full_walk`` skips the incremental feed and re-walks fully, which is the lever a
    scheduled "refresh" run uses to re-run **full-bit** on a change-feed host: full-bit only runs
    on a full walk (it needs the freshly-staged candidates to funnel), so an incremental-only host
    would otherwise never re-hash changed content and its dedup groups would freeze. A periodic
    forced full walk re-baselines and re-hashes; the change-guarded upsert keeps it cheap for the
    unchanged majority.

    Returns the scope outcome and the resolved :class:`VolumeInfo` on the full-walk path (so the
    caller can run the optional full-bit pass over the freshly-staged candidates), or ``None`` on
    an incremental cycle — a light-touch cycle stages no walk candidates to funnel, so full-bit is
    deferred to the next full walk.
    """
    volume = await backend.volume_info(root)
    # ADR-029 relabel: a configured per-scope label (the real host path behind a synthetic container
    # mount, e.g. /scan/docker_data → /mnt/docker_data) becomes the volume's display_name so the UI
    # shows the real path. The backend already sets display_name for remote volumes (mount_key) —
    # don't override that; this only fills the local-scan case the backend leaves None.
    if volume.display_name is None:
        label = config.scope_labels.get(root)
        if label:
            volume = volume.model_copy(update={"display_name": label})
    ack = WarningAck(
        operator=operator,
        acknowledged_at=datetime.now(tz=UTC),
        target=root,
        mode="metadata",
    )
    feed: ChangeFeed | None = None
    if not force_full_walk and staging.has_baseline_run(
        host_id=config.host_id, volume_id=volume.mountpoint
    ):
        try:
            feed = feed_factory(backend, volume, root, staging, config)
        except (OSError, RuntimeError) as exc:
            # A feed that raised while being constructed (e.g. probing snapshots/permissions) is
            # never trusted to be complete → fall back to a full walk (ADR-006 conservative path).
            _log.warning(
                "incremental feed unavailable; falling back to full walk",
                extra={"root": root, "error": str(exc)},
            )
            feed = None
    if feed is not None:
        incremental = IncrementalScanner(
            backend=backend, staging=staging, supervisor=supervisor, host_id=config.host_id
        )
        delta = await incremental.scan(root, feed, warning_ack=ack)
        _log.info(
            "incremental cycle complete",
            extra={
                "root": root,
                "upserts": delta.upserts_staged,
                "removals": delta.removals_staged,
            },
        )
        # rows_changed counts both upserts and explicit removals staged this cycle.
        rows_changed = delta.upserts_staged + delta.removals_staged
        return ScopeOutcome(root, delta.upserts_staged, rows_changed), None
    scanner = _scanner_for(backend, staging, supervisor, config, batch_size=batch_size)
    result = await scanner.scan(root, warning_ack=ack)
    return ScopeOutcome(root, result.entries_seen, result.rows_changed), result.volume


async def run_agent(
    config: AgentConfig,
    *,
    staging_path: str,
    operator: str,
    batch_size: int = 1000,
    push_chunk: int = 1000,
    drain: DrainFn | None = None,
    finalize: FinalizeFn | None = None,
    adapter: PlatformAdapter | None = None,
    adapter_pool: str | None = None,
    secret_provider: SecretProvider | None = None,
    registry: BackendRegistry | None = None,
    feed_factory: FeedFactory | None = None,
    force_full_walk: bool = False,
) -> AgentRunSummary:
    """Scan every scope into staging, then push to the core ingest endpoint.

    The backend for each scope is resolved via the :class:`BackendRegistry` rather than hardcoding
    POSIX — so the specialised plugins (ZFS, NTFS/exFAT, SMB, SFTP) are actually selected by
    capability (first-match-wins, ADR-004). Remote SMB/SFTP targets (``config.remote_targets``) are
    scanned as additional roots keyed by their ``mount_key``.

    Args:
        config: The validated agent configuration.
        staging_path: Path to the SQLite staging DB (created if absent).
        operator: Identity recorded on each scan run's impact acknowledgement (audit).
        batch_size: Entries staged per flush.
        push_chunk: Entries per ingest POST.
        drain: Override the push step (tests inject a fake). Defaults to the CA-pinned
            mTLS drain against ``config.ingest_url``.
        finalize: Override the post-drain rollup finalize (tests inject a fake). Defaults to a
            POST to ``/api/v1/agents/finalize`` over the same CA-pinned mTLS channel, which has
            the server recompute ``subtree_rollup`` for this host's freshly-ingested volumes
            (ADD 09 §8). A failure here is logged and swallowed — the deltas are already ingested,
            only the rollups lag until the next run.
        adapter: Optional control-plane :class:`PlatformAdapter` (ADD 04). When supplied with
            ``adapter_pool``, its ``pool.status`` feeds the supervisor's resync guard — the
            only resync signal on a pure-ZFS host with no ``/proc/mdstat`` (AR-0002) —
            and the ZFS backend's topology/resilver truth. A no-op when not given.
        adapter_pool: The pool whose resilver state gates full-bit scans on this host.
        secret_provider: Resolves SMB/SSH credential references for remote backends (ADR-010).
            Required only when ``config.remote_targets`` is non-empty.
        registry: Override the backend registry (tests inject one). Defaults to
            :func:`build_default_registry` wired with the adapter, pool, and remote targets.
        feed_factory: Override the incremental change-feed resolver (tests inject a fake feed).
            Defaults to :func:`_default_feed_for`. On the FIRST scan of a ``(host, volume)`` the
            agent always full-walks (the warned baseline); on subsequent runs it asks this factory
            for a :class:`ChangeFeed` and stages only deltas + deletions (ADR-006). A factory that
            returns ``None`` (or raises) for a scope means "no feed can run here" → the agent falls
            back to a full walk rather than risk missing a change.
    """
    started_at = datetime.now(tz=UTC)
    feed_factory = feed_factory or _default_feed_for
    backends = registry or build_default_registry(
        adapter,
        pool=adapter_pool,
        walk_concurrency=config.throttle.walk_concurrency,
        remote_targets=config.remote_targets,
        secret_provider=secret_provider,
    )
    if adapter is not None and adapter_pool is not None:
        supervisor = LoadSupervisor(
            config.throttle,
            resync_provider=adapter_resync_provider(adapter, adapter_pool),
        )
    else:
        supervisor = LoadSupervisor(config.throttle)
    scopes: list[ScopeOutcome] = []
    # Local scope roots are gated by the scan_scope allow-list; remote targets are their own
    # allow-list (a configured target is in-scope by construction). Both still re-enforced
    # server-side (AR-0012).
    local_roots = [(root, True) for root in config.scan_scope]
    remote_roots = [(target.mount_key, False) for target in config.remote_targets]

    try:
        with StagingStore(staging_path) as staging:
            for root, scope_gated in [*local_roots, *remote_roots]:
                if scope_gated and not config.in_scope(root):
                    scopes.append(ScopeOutcome(root, 0, 0, error="not within scan_scope"))
                    continue
                try:
                    backend = backends.resolve(root)
                except NoBackendError as exc:
                    _log.error("no backend for scope", extra={"root": root, "error": str(exc)})
                    scopes.append(ScopeOutcome(root, 0, 0, error=str(exc)))
                    continue
                try:
                    outcome, volume = await _scan_one_scope(
                        backend=backend,
                        staging=staging,
                        supervisor=supervisor,
                        config=config,
                        operator=operator,
                        root=root,
                        batch_size=batch_size,
                        feed_factory=feed_factory,
                        force_full_walk=force_full_walk,
                    )
                except (OSError, RuntimeError, sqlite3.Error) as exc:
                    # sqlite3.Error (staging-DB lock / disk-full / I/O error) subclasses only
                    # Exception, not OSError/RuntimeError — without it a staging failure on ONE
                    # scope would propagate and abort the whole run (every remaining scope, the
                    # drain, finalize and run report), violating the per-scope isolation invariant.
                    _log.error("scan of scope failed", extra={"root": root, "error": str(exc)})
                    scopes.append(ScopeOutcome(root, 0, 0, error=str(exc)))
                    continue
                # Optional full-bit pass: only for local roots within the fullbit allow-list, and
                # only after the metadata pass has staged the candidates it funnels over. Skipped on
                # an incremental cycle's volume==None path (a feed-only cycle stages no walk
                # candidates to funnel) — full-bit re-evaluates against the full baseline next walk.
                if scope_gated and volume is not None and config.in_fullbit_scope(root):
                    # The full-bit pass is OPTIONAL — the metadata result is already complete and
                    # (after the drain) ingested. Any failure here (incl. a staging sqlite3.Error
                    # from collision_sizes/candidates_of_size, which _run_fullbit's inner handler
                    # doesn't catch) must record fullbit_error and continue, never abort the run.
                    try:
                        await _run_fullbit(
                            backend=backend,
                            staging=staging,
                            supervisor=supervisor,
                            config=config,
                            operator=operator,
                            root=root,
                            volume=volume,
                            outcome=outcome,
                        )
                    except (OSError, RuntimeError, sqlite3.Error) as exc:
                        outcome.fullbit_error = str(exc)
                        _log.error("full-bit pass failed", extra={"root": root, "error": str(exc)})
                scopes.append(outcome)

            drain_fn = drain or (lambda s: _mtls_drain(config, s, push_chunk=push_chunk))
            pushed = await drain_fn(staging)
            # Have the server recompute subtree rollups for the volumes this run just landed, so
            # the UI tree/treemap show sizes (ADD 09 §8). Runs once, after the drain, over the same
            # mTLS/proxy boundary. Best-effort: the catalogue rows are already ingested, so a
            # finalize failure only delays the rollups — it must never abort an otherwise-good run.
            finalize_fn = finalize or (lambda: _mtls_finalize(config))
            try:
                finalized = await finalize_fn()
            except Exception as exc:  # finalize is best-effort; never fail an ingested run
                finalized = None
                _log.warning("rollup finalize failed", extra={"error": str(exc)})
    finally:
        # Release the persistent control-plane session, if any (ADD 04). Teardown must never
        # mask a scan/push error, so it is best-effort and logged, not raised.
        if adapter is not None:
            try:
                await adapter.close()
            except Exception:  # teardown is best-effort; never mask the scan/push result
                _log.warning("adapter close failed during teardown", extra={"swallowed": True})

    summary = AgentRunSummary(
        host_id=config.host_id,
        scopes=scopes,
        pushed=pushed,
        finalized=finalized,
        started_at=started_at,
        finished_at=datetime.now(tz=UTC),
    )
    _log.info(
        "agent run complete",
        extra={
            "host_id": summary.host_id,
            "entries_seen": summary.entries_seen,
            "pushed": summary.pushed,
            "finalized": summary.finalized,
            "failed_scopes": summary.failed_scopes,
        },
    )
    return summary


async def scan_one_root_now(
    config: AgentConfig,
    *,
    root: str,
    mode: Literal["metadata", "fullbit"],
    staging_path: str,
    operator: str,
    batch_size: int = 1000,
    push_chunk: int = 1000,
    drain: DrainFn | None = None,
    finalize: FinalizeFn | None = None,
    adapter: PlatformAdapter | None = None,
    adapter_pool: str | None = None,
    secret_provider: SecretProvider | None = None,
    registry: BackendRegistry | None = None,
    feed_factory: FeedFactory | None = None,
) -> AgentRunSummary:
    """Scan exactly one in-scope local ``root`` NOW (Scan Now, P3) — reuses :func:`run_agent`.

    Builds a one-root scoped view of ``config`` (``scan_scope == [root]``, no remote targets) and
    runs the SAME scan -> stage -> push -> finalize pipeline as a full agent run, restricted to that
    root. ``mode='metadata'`` suppresses the full-bit pass (empty ``fullbit_scope``) for a pure
    metadata refresh; ``mode='fullbit'`` keeps the full-bit pass ONLY when ``root`` is already in
    the host's ``fullbit_scope`` (content-hashing can never widen the host's standing full-bit
    allow-list — defence-in-depth, fullbit-dedup). ``force_full_walk=True`` so an immediate Scan Now
    re-walks fully (and, for full-bit, re-funnels the freshly-staged candidates) rather than taking
    the light-touch incremental path.

    Scope note: because the scoped view sets ``scan_scope = [root]``, ``run_agent``'s own per-root
    ``in_scope`` gate trivially passes for ``root`` — so the caller MUST have already verified
    ``root`` lies within the agent's *real* ``scan_scope`` (the actor's defence-in-depth refusal;
    see :class:`fathom.agent.actor.dispatch.ScanDispatcher`). The server re-enforces scope on
    ingest regardless (AR-0012).
    """
    fullbit_now = mode == "fullbit" and config.in_fullbit_scope(root)
    # Narrow, never widen: model_copy carries every transport/identity/secret field unchanged and
    # only restricts what is scanned this run. (No re-validation needed — both lists are subsets of
    # already-validated config, trivially satisfying fullbit ⊆ scan_scope.)
    scoped = config.model_copy(
        update={
            "scan_scope": [root],
            "fullbit_scope": [root] if fullbit_now else [],
            "remote_targets": [],
        }
    )
    return await run_agent(
        scoped,
        staging_path=staging_path,
        operator=operator,
        batch_size=batch_size,
        push_chunk=push_chunk,
        drain=drain,
        finalize=finalize,
        adapter=adapter,
        adapter_pool=adapter_pool,
        secret_provider=secret_provider,
        registry=registry,
        feed_factory=feed_factory,
        force_full_walk=True,
    )
