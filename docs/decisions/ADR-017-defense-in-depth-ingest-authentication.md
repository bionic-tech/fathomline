# ADR-017: Defence-in-depth ingest authentication (mTLS fingerprint + proxy shared secret)

**Status:** Accepted **Date:** 2026-06-06 **Deciders:** project owner

## Context
Agent-push over mTLS is the v1 ingest transport (ADR-002). An agent's authoritative identity is
its client-certificate fingerprint, never anything in the request body (`src/fathom/core/ingest.py`
re-derives the host from the fingerprint; the agent's own scope check is necessary but not trusted,
AR-0012). mTLS is terminated *upstream* at the nginx proxy
(the deployment stack's nginx proxy template, ADD 01 / AR-0020), which runs `ssl_verify_client on`
against the Fathom CA (`ssl_client_certificate /certs/fathom-ca.crt`, `ssl_verify_depth 2`) and then
**overwrites** `X-Client-Cert-Fingerprint` with the verified `$ssl_client_fingerprint` before
proxying to `http://api:8080`. `proxy_set_header` replaces any client-supplied copy, so a client
*through the proxy* cannot forge that header.

The problem is the path *around* the proxy. The core's ingest listener is reachable on the internal
`fathom` docker network (and on localhost), and the proxy is the *only intended* route to it
(AR-0020). A direct call that bypassed the proxy could set `X-Client-Cert-Fingerprint` to any value;
the core, trusting the header on its face, would accept it. Because the fingerprint *is* the host
identity and `_upsert_host` auto-enrols an unseen fingerprint as a new `host` row
(`src/fathom/core/ingest.py`, the `existing is None` branch creates `Host(...)`), anyone reachable on
the port could forge an agent identity, enrol a host, and poison the catalogue. That is the
forged-fingerprint spoof (AR-0010, STRIDE Spoofing). Terminating mTLS upstream is the right call
(off-loads cert verification, single boundary), but it means the core cannot itself see the TLS peer
— it must be told, and being told is forgeable unless the *channel* of the telling is
authenticated.

The human-auth surface is a separate boundary and out of scope here: read != write, the agent ingest
route is never fronted by human SSO, and the human-auth dependency must never be attached to it
(`src/fathom/api/deps.py` module docstring; AR-0012; ADR-009 for the human path).

## Decision
Add a **deployment shared secret** as a second, independent factor that proves a request transited
the mTLS boundary, so the injected fingerprint is trusted *only* when it provably came through the
proxy.

- The proxy injects a shared secret alongside the fingerprint. Both `proxy_set_header` lines sit in
  the single `location /api/v1/agents/` block in the deployment stack's nginx proxy template:
  `X-Client-Cert-Fingerprint $ssl_client_fingerprint` and `X-Fathom-Proxy-Secret
  "${FATHOM_INGEST_PROXY_SECRET}"`. The secret is the only env var the nginx image substitutes into
  the rendered config at start.
- The core requires the secret when configured and **fails closed**. `require_client_fingerprint`
  (`src/fathom/api/deps.py`) reads `settings.ingest_proxy_secret`; when it is set, the request must
  carry a matching `X-Fathom-Proxy-Secret` (header name constant `PROXY_SECRET_HEADER`) or the
  request is rejected `401 "ingest must transit the trusted proxy"`. The comparison is
  **constant-time** (`hmac.compare_digest`), so a wrong or missing secret leaks no timing signal.
  Only after the proxy check passes is the fingerprint header read; an empty fingerprint is itself a
  `401 "client certificate required"`.
- The secret is wired in deployment as a required value: `FATHOM_INGEST_PROXY_SECRET` is set on both
  the `api` and `proxy` services in the deployment stack's `docker-compose.yml` with the `:?` guard (compose
  refuses to start if it is unset in `.env`), so the two ends share one value by construction.
- When no secret is configured (dev/test) the proxy check is skipped and the fingerprint header is
  trusted directly — the boundary collapses to a single factor by design, for environments with no
  proxy in front.
- **Host identity = the cert fingerprint.** The CA is the trust gate: `ssl_verify_client on` rejects
  any client without a CA-signed cert at the TLS handshake, so only certs the Fathom CA issued ever
  produce a forwarded fingerprint. On first push, `_upsert_host` auto-enrols the host keyed on
  `cert_fingerprint` (`src/fathom/core/ingest.py`); subsequent pushes update `os`, `agent_version`,
  and `last_seen` on the matched row.

### Alternatives considered
- **Trust the `X-Client-Cert-Fingerprint` header directly (no second factor).** Rejected: the header
  is forgeable on any call that bypasses the proxy, and the ingest listener is reachable on the
  internal network / localhost. This is exactly the spoof the decision closes (AR-0010, STRIDE
  Spoofing).
- **Network ACL only (firewall/listener binding so only the proxy can reach the core).** Rejected as
  the *sole* control: brittle and a single misconfiguration (a republished port, a wider bind, a
  co-located container on the `fathom` network) silently reopens the spoof, with no signal at the
  core. The shared secret makes trust depend on a value only the proxy holds, not on topology
  staying correct. Network scoping remains a defence-in-depth layer (the `api` service publishes its
  API port on localhost only — `${FATHOM_API_BIND:-127.0.0.1}:${FATHOM_API_PORT:-8088}:8080`,
  `docker-compose.yml` — with no LAN-exposed agent port, so the proxy is the only LAN ingest route),
  but it is not relied upon for the identity guarantee.

## Consequences
### Positive
- The fingerprint is trusted **only** when it provably transited the mTLS boundary; a direct,
  proxy-bypassing call lacks the secret and is rejected (`401`), closing the forged-fingerprint
  spoof (AR-0010, STRIDE Spoofing).
- Two independent factors gate auto-enrolment: the CA-signed cert (handshake) *and* the proxy secret
  (channel proof). Neither alone enrols a host.
- Constant-time secret compare (`hmac.compare_digest`) gives no timing oracle on the secret.
- Compose's `:?` guard on `FATHOM_INGEST_PROXY_SECRET` makes a production deployment that forgot the
  secret fail to start, rather than fall back to single-factor silently.
- The control is config-driven and absent by default in dev/test, so local runs and the test suite
  need no proxy to exercise ingest.

### Negative
- One more shared secret to provision, rotate, and keep in sync across the `api` and `proxy` services
  (managed via `.env` / the secret backend, ADR-010). The two ends must hold the *same* value or all
  ingest 401s.
- A single deployment-wide secret authenticates the *channel*, not each agent — it is not a
  per-agent credential. Per-agent identity still rests entirely on the mTLS cert; the proxy secret
  only proves "came through the proxy", which is its intended scope.

### Risks
- **Secret/cert recovery footgun.** An `rsync --delete` (with `certs/` not excluded) already removed
  the deployment stack's `certs/*` including the Fathom CA key; the proxy kept serving on in-memory certs, so
  a reboot would leave it crash-looping with no cert files. Because host identity *is* the
  fingerprint, regenerating the chain changes every client fingerprint and would orphan the existing
  catalogue. The recovery is scripted in the deployment stack's cert-recovery script: regenerate CA + server +
  client, recompute the new client fingerprint (`sha1` of the DER cert, lowercase hex — matching
  nginx's `$ssl_client_fingerprint`), **re-point host `id=1` at the new fingerprint** so its
  multi-million-row catalogue is not orphaned, then recreate the proxy on the fresh certs. This is
  tracked as an open recovery item; run the script on the core host once it is reachable.
- **Secret leakage** (e.g. into logs or the rendered `nginx.conf`) would let an attacker on the
  internal network forge the channel proof and re-open the spoof; mitigated by keeping it in the
  secret backend (ADR-010), never in code/`.env`-in-repo, and never logging header values.
- **Misconfiguration to the open side:** leaving `ingest_proxy_secret` unset in an exposed
  deployment reverts to trusting the fingerprint header directly. The compose `:?` guard mitigates
  this for the reference deployment stack, but any new deployment topology must set the secret deliberately.
