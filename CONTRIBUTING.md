# Contributing to Fathomline

Thanks for your interest! Fathomline is young (alpha), so the most valuable contributions right now
are **bug reports from real estates** ("this assumption breaks on my NAS"), portability fixes,
and test coverage — but features and docs are welcome too.

## Development setup

Backend (Python 3.12, managed with [uv](https://docs.astral.sh/uv/)):

```bash
uv sync --extra dev          # creates .venv with runtime + dev tools
```

Web UI (Node 20+):

```bash
cd src/fathom/web && npm ci
```

Run the whole thing locally with real data (SQLite, no fleet needed):

```bash
scripts/localdev/run.sh      # http://127.0.0.1:8099, admin / localdev-admin-pw
```

## Quality gate

Every PR must pass the same gate CI runs. Locally:

```bash
uv run ruff check . && uv run ruff format --check .   # lint + formatting
uv run mypy src                                       # strict typing
uv run pytest                                         # ~800 hermetic tests, no network needed
cd src/fathom/web && npm run typecheck && npm run lint && npm test && npm run build
```

The Python suite is fully hermetic — no Docker, no Postgres, no real hosts required. If your
change needs live infrastructure to test, add a hermetic test with a fake transport (see
`tests/deploy/fakes.py` and `tests/adapters/` for the pattern) alongside any manual notes.

## Conventions

- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) —
  `feat(scope): …`, `fix(scope): …`, `docs: …`, `test: …`. Keep subjects ≤ 72 chars.
- **Branches**: `feat/…`, `fix/…`, `docs/…`, `chore/…`; short-lived, merged via PR.
- **Python style**: enforced by ruff (incl. bugbear, async-pitfalls, bandit) and
  `mypy --strict`. No blocking I/O on the event loop — offload to `asyncio.to_thread`.
- **TypeScript**: strict mode, no `any`, every chart paired with an accessible data-table
  alternative.
- **Comments** explain *why*, not *what*. Design rationale lives in
  [docs/decisions/](docs/decisions/) (ADRs) — significant design changes should add or amend
  an ADR.

## Security-sensitive areas

The ingest identity boundary, auth/RBAC, remediation (write path), preview sandbox, and the
deployment subsystem have been through adversarial review and carry regression tests for every
finding. Changes there get extra scrutiny:

- never weaken a fail-closed default,
- keep the audit-before-act ordering on the write path,
- add a regression test for any boundary you touch.

If you think you've found a vulnerability, **do not open a public issue** — see
[SECURITY.md](SECURITY.md).

## Pull requests

1. Fork, branch, make the change, keep the gate green.
2. Update docs/tests alongside code (a feature without tests isn't done).
3. Fill in the PR template — especially "how was this verified".
4. One logical change per PR; smaller is faster to review.

By contributing you agree your contributions are licensed under [AGPL-3.0](LICENSE).
