# Fathomline — The Story

> _Fathomline — sound out your storage estate._ · by Bionic Technologies · built on the Fathom engine

> Two tellings of the same story. **Part A** is the human "where it came from / why it exists"
> version — for homelabbers and small-business owners. **Part B** is the **technical path** — the
> same journey told through the engineering decisions, for developers, contributors, and anyone
> reading the ADRs. Read whichever fits — or run A then B.

---

## Part A — The Story (for people who run their own kit)

### The question nobody could answer

Anyone who runs their own infrastructure knows the feeling. The NAS fills up. A backup job fails at
2am because a volume hit 100%. You open a disk tool, stare at a treemap of *one* machine, reclaim a
few gigs, and move on — until it happens again on a different box a month later.

The honest answer to "where did all my space go?" was never on one machine. It was spread across the
NAS, the two servers, the old workstation that's now a backup target, and the cloud bucket you forgot
you were paying for. No single tool could see the whole estate. You were measuring puddles while
standing in a lake.

### A rope, a weight, and the deep

Before sonar, sailors measured depth with a **fathomline** — a weighted rope, knotted at intervals,
lowered over the side until the lead hit bottom. Simple, honest, and it told you exactly what was
down there before you ran aground.

That's the whole idea. Fathomline drops a sounding line into your storage estate — every host, all at
once — and tells you what's *really* down there. Not a guess, not one machine: a measured picture of
the deep across everything you run.

### Built on real metal, not a whiteboard

Fathomline wasn't designed in the abstract. It grew out of Bionic Technologies' own infrastructure —
a working fleet of machines (a TrueNAS box, a couple of operational servers, some Docker hosts)
carrying tens of millions of files and well over a hundred terabytes. The tool had to answer real
questions on real hardware before it was allowed to call itself finished: *which host is growing
fastest? what's duplicated across machines? what can I safely reclaim — and prove I did it safely?*

It started life under a different name (**StrataScope** — the layers-of-sediment idea), but the
sounding-line metaphor was truer to what it does, and **Fathomline** stuck.

### Why we're giving it away

Bionic Technologies builds a commercial network-observability product for people who pay for it.
**Fathomline** is the other half of the bargain: it's **free and open source**, AGPL-3.0, a gift to
the homelab and self-hosting community that taught most of us how this stuff actually works.

We think the people who run their own racks, NAS boxes, and home servers deserve a serious tool — not
a stripped-down "community edition" with the good parts paywalled. Fathomline is the real thing: the
same engine, the same safety spine, the same code that runs on our own fleet every night.

### Safety is the feature

There's a reason most "disk cleaner" tools feel a bit dangerous: they're one wrong click from
deleting something you needed. Fathomline was built the other way round. By default it only **reads**
— it never touches a file unless you explicitly turn remediation on, select exactly what goes,
approve it, and it's all **signed, reversible, and written to a tamper-evident log**. Quarantine
first, delete later, prove every step. You should be able to trust a tool with root on your storage.
Most you can't. This one you can audit.

### Who it's for

The person with a Proxmox box and a Synology in the cupboard. The small business with a server in the
corner and no full-time sysadmin. The homelabber with four machines and a growing sense of dread
every time a disk hits 90%. If you run storage you can't fully see, Fathomline is the rope that tells
you how deep it really is.

> **The one-liner:** *Fathomline — sound out your storage estate.*

---

## Part B — The Technical Path (how it was actually built)

The same story, told through the engineering — for contributors and anyone reading the decision
records.

### Premise

Single-host disk analyzers (ncdu, WinDirStat, et al.) solve the wrong scope. The real problem is an
**estate**: many hosts, mixed filesystems (ZFS, NTFS, exFAT, SMB/SFTP shares, cloud remotes), no
central catalogue, and no safe way to act on what you find. Fathomline is built as a distributed
system around that premise.

### The architecture in one breath

A lightweight **read-only agent** runs on each host, walks the filesystem, and **pushes** file
metadata over **mTLS** into a central **PostgreSQL** catalogue (SQLite for staging and single-host
setups). A FastAPI control plane serves a React/TypeScript UI — treemaps, estate-wide search, growth
trends, churn feeds, cross-host duplicate detection. Remediation, when enabled, runs through a signed,
reversible, fully-audited action pipeline. The core never touches your filesystem directly; the
agents do, and they're built to be boring and safe.

### The path, stage by stage

The product was delivered in deliberate stages, each gated before the next:

1. **Read-only foundation.** Per-host scanning with self-throttling (I/O class limits, concurrency
   budgets, load-aware auto-pause) so a scan never harms a production box. Resumable staging in
   SQLite.
2. **Catalogue + ingest.** Agent-push over mTLS into a partitioned PostgreSQL catalogue; immutable
   per-run snapshots so growth and churn become first-class, queryable history.
3. **Content hashing + dedup.** Progressive verification — size → head/tail sample → full **BLAKE3**
   — to find true duplicates across hosts and report reclaimable bytes, without ever auto-deleting.
4. **The safety spine.** Opt-in, default-OFF remediation: human-selected dry-run plans,
   **Ed25519-signed** single-use action jobs, quarantine-first reversibility, content drift re-check
   at the execution boundary, and a hash-chained tamper-evident audit log.

Everything since has been depth and breadth on that spine: more storage backends, sandboxed file
previews (per-request gVisor), cross-host reconciliation, an agent deployment wizard, a pluggable
local-first inference layer for content-aware suggestions, a natural-language concierge, and an
in-app settings/onboarding/notifications suite.

### Decisions, on the record

Fathomline keeps **Architecture Decision Records** (40-plus and counting). They are the technical
story in primary sources — why agent-push over mTLS instead of a central crawler (ADR-002), why
PostgreSQL + SQLite (ADR-003), why a `StorageBackend` protocol instead of hard-coding filesystems
(ADR-004), why remediation ships but locked behind human approval (ADR-011), how the audit chain is
made fork-proof (ADR-019). If you want to understand *why* the code looks the way it does, start in
[`docs/decisions/`](decisions/) (indexed in the [documentation index](README.md)).

### Standards, not vibes

The codebase runs to strict quality gates — `ruff`, `mypy --strict`, a large hermetic backend test
suite, TypeScript strict + vitest on the frontend, all green on the main branch. It went through an
**adversarial security review** (multiple personas across several attack dimensions); the findings
were fixed and the fixes are now regression tests. This is a tool you're meant to give root over your
storage, so it's held to the standard that implies.

### Lineage

Fathomline shares engineering DNA with Bionic's commercial platform — the same discipline, the same
security-first instincts — but it's a **standalone product** by design (ADR-001), decoupled so it can
live in the open under AGPL-3.0 without dragging commercial code along. The engine package and
`FATHOM_*` configuration keep the original **Fathom** codename; **Fathomline** is the product and
brand built around it.

> **Attribution:** Fathomline — by Bionic Technologies. Engine codename: Fathom.

---

*Continue: [Documentation index](README.md) · [Roadmap](../ROADMAP.md) · [Backlog](../TODO.md) ·
[Architecture Decision Records](decisions/)*

© 2026 Bionic Technologies Ltd. Fathomline is AGPL-3.0; the Fathomline name and logos are trademarks
of Bionic Technologies Ltd (see [`assets/brand/`](../assets/brand/README.md)).
