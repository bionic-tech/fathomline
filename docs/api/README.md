# Fathomline API reference

[`openapi.json`](openapi.json) is the committed OpenAPI 3.1 spec for the Fathomline HTTP API,
generated from the code. A test (`tests/api/test_openapi.py`) fails the build if it drifts, so this
reference always matches the running API.

## View it

- **Locally, no install:** open [`index.html`](index.html) in a browser (renders `openapi.json`
  with Redoc).
- **Online:** paste `openapi.json` into <https://editor.swagger.io> or the
  [Redocly playground](https://redocly.github.io/redoc/).
- **CLI:** `npx @redocly/cli preview-docs docs/api/openapi.json`

## Regenerate

After any change to a route or a request/response model:

```bash
python scripts/export_openapi.py
```

## Auth model (not yet expressed as OpenAPI `securitySchemes`)

The spec describes request/response shapes but does not yet declare formal security schemes
(the API authenticates via custom dependencies rather than FastAPI's built-in security utilities).
In short:

- **Human/UI routes** — server-side session cookie (login + optional step-up MFA); deny-by-default
  RBAC with per-host/volume scope. Destructive routes require fresh step-up MFA.
- **Agent ingest routes** (`/api/v1/agents/...`) — mutual-TLS client-certificate fingerprint,
  verified at the proxy; never human auth.
- **Enrolment bundle/image routes** — a single-use, short-TTL bearer token.

Declaring these as OpenAPI `securitySchemes` + per-route requirements is a tracked follow-up.
