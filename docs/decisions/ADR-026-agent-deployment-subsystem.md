# ADR-026 — Agent Deployment Subsystem (push + pull enrollment)

**Status:** Proposed (2026-06-10)
**Deciders:** project owner, Fathom core
**Related:** ADR-010 (secrets by-reference), ADR-011/025 (remediation + agent-initiated dispatch), ADD 03/13 (auth, RBAC, step-up MFA)

## Context

Bringing a new host into the fleet today is a manual, multi-step ritual (mint a CA-signed client
cert with `openssl`, `docker save | load` the image, drop a per-host `docker-compose.yml` +
`agent.config.yaml` + `certs/`, `compose up`). The owner wants a **GUI wizard**: add a host by
FQDN/IP, supply admin credentials, click **Deploy** — and ideally deploy in **batches**.

This crosses a line Fathom has deliberately held. Today the trust model is **agent-initiated
inbound only**: agents dial *in* to core over mTLS; **core never connects out** to a fleet host and
holds **no** fleet-access credentials. A push wizard means core gains an SSH client that runs
privileged commands on arbitrary machines and transiently handles operator credentials — a powerful
new capability and a real new attack surface.

## Decision

Add a **default-OFF, `DEPLOY_AGENT`-capability + step-up-MFA gated** deployment subsystem offering
**two** enrollment modes, so the operator can pick per-host based on how much trust to hand core:

### Mode A — PUSH (core → target over SSH)
The UX the owner described. Per host: **preflight** (target reachable, Docker present, target can
reach `proxy:9443`) → **mint** a CA-signed client cert in-process → **transfer** the agent image
(`docker save` streamed over SSH → `docker load`) → **drop** the bundle (compose + config + certs)
via SFTP → `compose up -d agent` → **verify** the agent enrolls. Runs as a background task; the
wizard polls per-host status.

### Mode B — PULL (target self-enrolls; no SSH-out)
Core issues a **short-lived signed enrollment token** and shows a one-line bootstrap command. The
operator runs it on the target; the target fetches its bundle + cert over the existing mTLS/HTTPS
boundary, installs, and starts itself. **Core never connects out and never holds the target's
admin credentials.** This is the safer default (Tailscale/k8s node-join model); the trade-off is
one paste per box. Batch = a generated list of commands.

### SSH auth (push), all transient — never persisted, repr-redacted, resolved in-memory only
- **SSH private key + optional passphrase** (the fleet's actual model; most likely to work).
- **Username + password** (often disabled on hardened hosts — offered, not assumed).
- **CA-signed OpenSSH user certificate** (key + cert).
- **Optional sudo password** for hosts without passwordless sudo (separate from SSH login).
- **Host-key policy:** preflight shows the target host-key fingerprint and lets the operator pin it
  (recorded in the deploy audit, TOFU); a **changed** pinned key aborts the connect before any
  command. Pinning is **mandatory for password auth** (the password would otherwise reach an
  unverified host) and **recommended for key auth** (which proves identity with a challenge-bound
  signature, so a first-contact mismatch leaks no secret). No blind `AutoAddPolicy`.

### Two distinct certificates (kept separate on purpose)
- **SSH login credential** — authenticates core *to the target* (push only). May be passphrase-
  protected → we accept an optional passphrase.
- **Fathom mTLS client cert** — the *agent's* identity to Fathom. **Minted by the subsystem**
  (CA-signed, `CN=<host>-agent`, EKU clientAuth), kept **passphrase-less** (machine cert, 0600 file
  perms). The operator never handles a passphrase for this one.

### Cert minting & the CA key
Client certs are minted **in-process** with `cryptography` (RSA-2048 signed by the Fathom CA),
matching `deploy/mint-agent-cert.sh`. The CA **private key** is provisioned **by reference**
(`agent_deployment_ca_key_ref` → env/Docker-secret, ADR-010), never embedded. **Elevated trust
acknowledged:** a core that can mint client certs can mint *any* agent identity — this is exactly
why the subsystem is default-OFF, capability+MFA gated, and fully audited.

### Image delivery
Core is configured with a **pre-built image archive** (`agent_deployment_image_archive_path` — a
`docker save | gzip` tarball on a mounted volume). **Push** streams that archive to the target over
**chunked SFTP** then `docker load`s it — skipped when `docker image inspect` shows the image is
already present. **Pull** serves the same archive over HTTPS (token-gated) for the bootstrap's
`curl … | docker load`. With no archive configured the image is assumed already present (the v1
default). A private registry / `docker pull` path is a future optimisation, not v1.

### Batch & status
A deploy **run** fans out over a host list with **bounded concurrency** (semaphore, mirroring the
preview worker). Per-host status lives in an **in-memory run registry** on `app.state`; a run that
dies on restart is re-issuable. Every state transition is on the **durable hash-chained audit**
(audit-before-act).

### Single-worker requirement (normative)
Both the enrollment-token registry and the run registry are **per-process in-memory** state, exactly
like ADR-025's dispatch queue. **Core MUST run a single worker** (the deployed uvicorn has no
`--workers`, and the core container is not replicated behind the proxy). With more than one worker,
the registries diverge per worker and the surface **silently breaks**: an enrollment token issued on
worker A `403`s when the target's bundle/image fetch lands on worker B, and a deploy run created on A
`404`s when the wizard's status poll round-robins to B. There is no portable in-app way to read the
worker count, so this is enforced by deployment convention + documented here and at the
`DeployRuntime` registries; the provisioning log notes the assumption.

## Security posture (the crux)

| Concern | Mitigation |
|---|---|
| Trust-model inversion (core SSHes out) | Default-OFF; `DEPLOY_AGENT` capability + **fresh step-up MFA**; PULL mode avoids SSH-out entirely |
| Operator creds in core | **Transient only** — used in-memory for one deploy, never written to DB/disk/logs; redacted `__repr__` |
| CA signing key in core | By-reference (ADR-010); subsystem gated; minting is audited |
| MITM on first SSH contact | Host-key TOFU: a changed pinned key aborts; pin **mandatory for password auth**, recommended for key auth |
| Stolen pull token | Opaque random bearer, **SHA-256-hashed at rest**, single-use, short TTL (default 15 min), scoped to one `host_id` |
| Blind blast radius | Preflight before any change; per-host audit; batch concurrency cap |
| Bootstrap endpoint abuse (pull) | Token-authenticated (Bearer header), TTL + single-use; serves only the one scoped bundle |

## Consequences
- **Positive:** one-click/one-paste enrollment, automated cert minting, batch onboarding, the manual
  `openssl`/`save`/`load` ritual disappears.
- **Negative / accepted:** core gains an (gated, optional) SSH-out capability and the CA signing key;
  more moving parts; needs a live smoke test before trusting it in anger.
- **Default unchanged:** with `agent_deployment_enabled=false` (default) the routes 503 and nothing
  new is reachable — identical posture to today.

## Alternatives considered
- **Pull-only** (no push): safest, but doesn't match the owner's described one-click UX → we ship both.
- **Config-management tool** (Ansible/Salt): heavier external dependency + its own credential store;
  overkill for a handful of hosts and counter to Fathom's self-contained posture.
- **Persisted SSH credentials** for re-deploys: rejected — violates ADR-010 and widens the blast
  radius; re-deploy re-prompts.
