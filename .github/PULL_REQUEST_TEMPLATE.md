## What & why

<!-- One paragraph: what changes, and the problem it solves. Link the issue if there is one. -->

## How was this verified?

<!-- Commands run, tests added, manual checks against localdev. "Gate green" means:
     uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest
     cd src/fathom/web && npm run typecheck && npm run lint && npm test && npm run build -->

- [ ] Quality gate green locally
- [ ] New/changed behavior is covered by a test
- [ ] Docs / ADR updated if this changes a design decision or user-facing behavior

## Security-relevant?

<!-- Does this touch ingest identity, auth/RBAC, the write path, the sandbox, or deployment?
     If yes: which fail-closed defaults did you preserve, and which regression test covers it? -->
