# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for suspected vulnerabilities.**

Use GitHub's private vulnerability reporting ("Report a vulnerability" under the repository's
**Security** tab). You'll get an acknowledgement within 72 hours and a status update at least
weekly until resolution. Coordinated disclosure is appreciated; credit is given unless you
prefer otherwise.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest release (0.x) | ✅ |
| anything older | ❌ — 0.x is alpha; please upgrade |

## Security posture (summary)

Fathomline is designed around a read/write asymmetry: **everything that reads is on by
default, everything that writes is off by default** and individually gated.

- **Agent identity**: mTLS client certificates against a private CA, terminated at the proxy;
  the core verifies a proxy-shared secret with a constant-time comparison so a forged
  fingerprint header on a direct connection is rejected.
- **Human auth**: Argon2id passwords, TOTP MFA, server-side sessions (httpOnly, Secure,
  SameSite=strict, hashed at rest), optional forward-auth/OIDC with algorithm allow-listing and
  SSRF-pinned metadata fetches.
- **Authorization**: deny-by-default RBAC; every route requires an explicit capability and a
  server-built scope filter. Destructive routes additionally require fresh step-up MFA.
- **Write path** (disabled by default): Ed25519-signed single-use jobs, nonce replay
  protection, quarantine-first reversible operations, full-content drift re-check before any
  mutation, blast-radius caps, hash-chained append-only audit with fork rejection.
- **Previews**: rendered in a per-request gVisor sandbox — no network, read-only rootfs, all
  capabilities dropped, CPU/memory/pid/decompression caps.
- **Supply chain**: locked dependencies (`uv.lock`, `package-lock.json`), gitleaks in
  pre-commit, strict CSP with no inline script or eval.

## Known limitations

- A handful of accepted-risk findings from internal adversarial reviews are tracked openly;
  all are on default-OFF subsystems or require already-privileged positions. They are
  documented in the repository's review notes and revisited each release.
- The agent's in-memory nonce store is suitable for single-agent hosts; clustered agent
  deployments should use a durable nonce store (planned).
- Fathomline is alpha software. Run the core on a trusted network segment and keep the write
  path disabled unless you have read the enablement runbook.
