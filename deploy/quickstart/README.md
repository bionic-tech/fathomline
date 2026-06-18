# Fathomline quickstart deployment

The smallest production-shaped Fathomline: **PostgreSQL + schema migration + API/UI** on one
machine, with no hardware assumptions. (If you just want to *see* Fathomline with real data in
60 seconds, [`scripts/localdev/run.sh`](../../scripts/localdev/README.md) is even quicker —
it uses SQLite and scans local directories. This stack is the one you grow into.)

## Prerequisites

- Docker with the compose plugin
- ~2 GB RAM free for the stack (tunable in `.env`)

## Bring it up

```bash
cd deploy/quickstart
cp .env.example .env        # set FATHOM_DB_PASSWORD + FATHOM_INGEST_PROXY_SECRET inside
docker compose up -d --build
```

Create the first admin (one-time; credentials come from the environment, never argv):

```bash
docker compose exec \
  -e FATHOM_BOOTSTRAP_ADMIN_USER=admin \
  -e FATHOM_BOOTSTRAP_ADMIN_PASSWORD='pick-a-strong-one' \
  api python -m fathom.admin create-admin
```

Open <http://127.0.0.1:8088/> and log in. The catalogue is empty until an agent pushes a scan.

## Next steps

- **Add scan agents.** Agents authenticate with client certificates against a private CA and
  push over an mTLS-terminating nginx proxy that stamps `FATHOM_INGEST_PROXY_SECRET` on
  forwarded requests. The built-in **Deploy wizard** automates this: provision a CA
  (`FATHOM_AGENT_DEPLOYMENT_CA_CERT_REF`/`_CA_KEY_REF`), enable the deployment subsystem
  (`FATHOM_AGENT_DEPLOYMENT_ENABLED=true`), and it mints per-host certs and pushes agents over
  SSH — or hands you a one-time enrolment command to paste on the target. Full walkthrough:
  [multi-host deployment guide](../../docs/guides/multi-host-deployment.md).
- **Expose it properly.** Keep the API on localhost until HTTPS (or your SSO/forward-auth
  proxy) fronts it; then set `FATHOM_SESSION_COOKIE_SECURE=true`.
- **Storage.** For ZFS hosts, switch the `fathom-pgdata` named volume to a bind mount on a
  dedicated dataset so snapshots/replication cover the catalogue.

## Tear down

```bash
docker compose down        # add -v ONLY if you also want to wipe the catalogue volume
```
