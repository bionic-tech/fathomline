// Agent deployment wizard (ADR-026). Two modes:
//   • Push — enter a host + SSH credentials, preflight, then deploy (batch). The core SSHes in,
//     mints the agent cert, uploads the bundle and starts the container.
//   • Pull — generate a one-time bootstrap command you paste on the target; no SSH-out, no
//     credentials handed to the core.
// DEPLOY_AGENT-gated + step-up MFA on the mutating actions (enforced server-side). Default-OFF:
// the server 503s until the deploy runtime is provisioned, surfaced here with a clear message.

import { useState } from "react";

import { ApiError } from "../../api/client";
import {
  useDeployAgents,
  useDeployBrowse,
  useDeployRun,
  useEnrollToken,
  useMfaVerify,
  usePreflight,
  useWhoAmI,
} from "../../api/queries";
import type {
  DeployHostIn,
  EnrollOut,
  PreflightOut,
  RemoteTargetIn,
  SshCredentialIn,
} from "../../api/types";
import { principalHas } from "../../auth/rbac";
import { DirTree } from "../common/DirTree";

type Mode = "push" | "pull";
type AuthMethod = "key" | "password";

function gateMessage(e: unknown): string | null {
  if (e instanceof ApiError) {
    if (e.status === 403)
      return "You lack the deploy_agent capability (admin only).";
    if (e.status === 503)
      return "Agent deployment is not enabled on this server. Provision the CA + set agent_deployment_enabled (ADR-026 runbook).";
  }
  return null;
}

function errorText(e: unknown, fallback: string): string {
  return (
    gateMessage(e) ??
    (e instanceof ApiError ? (e.problem.detail ?? e.problem.title ?? fallback) : fallback)
  );
}

// A remote scan target as edited in the form (all strings); converted to RemoteTargetIn on submit.
interface RemoteTargetRow {
  protocol: "rclone" | "smb" | "sftp";
  host: string;
  remotePath: string;
  share: string;
  username: string;
  passwordRef: string;
}

function blankRemoteTarget(): RemoteTargetRow {
  return { protocol: "rclone", host: "", remotePath: "/", share: "", username: "", passwordRef: "" };
}

/** Convert edited rows → RemoteTargetIn[], dropping blank rows and protocol-irrelevant fields. */
function buildRemoteTargets(rows: RemoteTargetRow[]): RemoteTargetIn[] {
  return rows
    .filter((r) => r.host.trim())
    .map((r) => {
      const t: RemoteTargetIn = {
        protocol: r.protocol,
        host: r.host.trim(),
        remote_path: r.remotePath.trim() || "/",
      };
      if (r.protocol === "smb" && r.share.trim()) t.share = r.share.trim();
      if (r.protocol !== "rclone") {
        // SMB/SFTP creds are SECRET REFERENCES (names), never the secret itself (ADR-010).
        if (r.username.trim()) t.username = r.username.trim();
        if (r.passwordRef.trim()) t.password_ref = r.passwordRef.trim();
      }
      return t;
    });
}

interface HostForm {
  target: string;
  port: string;
  hostId: string;
  authMethod: AuthMethod;
  username: string;
  privateKey: string;
  passphrase: string;
  certificate: string;
  password: string;
  sudoPassword: string;
  containerPath: string;
  hostPath: string;
  proxyHostIp: string;
  expectedHostKey: string;
  remoteTargets: RemoteTargetRow[];
}

function emptyForm(): HostForm {
  return {
    target: "",
    port: "22",
    hostId: "",
    authMethod: "key",
    username: "",
    privateKey: "",
    passphrase: "",
    certificate: "",
    password: "",
    sudoPassword: "",
    containerPath: "/scan/data",
    hostPath: "/mnt/data",
    proxyHostIp: "",
    expectedHostKey: "",
    remoteTargets: [],
  };
}

// Auto-derive the in-container "agent path" from a real host path picked on the target, so the
// operator picks ONE drive/folder and the scan mount + scope follow (no hand-kept prefix). The
// agent always mounts under /scan/<leaf>, e.g. host /mnt/tank → agent /scan/tank.
function deriveAgentPath(hostPath: string): string {
  const leaf = hostPath.replace(/[/\\]+$/, "").split(/[/\\]+/).filter(Boolean).pop();
  return `/scan/${leaf || "data"}`;
}

function buildCredential(f: HostForm): SshCredentialIn {
  const cred: SshCredentialIn = { username: f.username.trim() };
  if (f.authMethod === "key") {
    cred.private_key = f.privateKey;
    if (f.passphrase) cred.passphrase = f.passphrase;
    if (f.certificate) cred.certificate = f.certificate;
  } else {
    cred.password = f.password;
  }
  if (f.sudoPassword) cred.sudo_password = f.sudoPassword;
  return cred;
}

function buildHost(f: HostForm): DeployHostIn {
  const host: DeployHostIn = {
    target: f.target.trim(),
    port: Number(f.port) || 22,
    host_id: f.hostId.trim(),
    credential: buildCredential(f),
    proxy_host_ip: f.proxyHostIp.trim() || undefined,
    expected_host_key: f.expectedHostKey.trim() || null,
  };
  // A local mount is optional now — clear both paths for a remote-only agent (ADR-029).
  if (f.containerPath.trim() && f.hostPath.trim()) {
    host.mounts = [
      { container_path: f.containerPath.trim(), host_path: f.hostPath.trim(), fullbit: true },
    ];
  }
  const remote = buildRemoteTargets(f.remoteTargets);
  if (remote.length) host.remote_targets = remote;
  return host;
}

function RemoteTargetsEditor({
  rows,
  onChange,
}: {
  rows: RemoteTargetRow[];
  onChange: (rows: RemoteTargetRow[]) => void;
}): JSX.Element {
  const update = (i: number, patch: Partial<RemoteTargetRow>): void =>
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <fieldset className="fathom-form-grid">
      <legend>Remote scan targets (optional — rclone / SMB / SFTP)</legend>
      {rows.length === 0 ? (
        <p className="fathom-muted">
          None. Add a cloud (rclone) or SMB/SFTP share for this agent to scan remotely.
        </p>
      ) : null}
      {rows.map((r, i) => (
        <div key={i} className="fathom-inline-field fathom-field-wide">
          <select
            aria-label={`Remote target ${i + 1} protocol`}
            value={r.protocol}
            onChange={(e) => update(i, { protocol: e.target.value as RemoteTargetRow["protocol"] })}
          >
            <option value="rclone">rclone</option>
            <option value="smb">SMB</option>
            <option value="sftp">SFTP</option>
          </select>
          <input
            type="text"
            aria-label={`Remote target ${i + 1} host`}
            placeholder={r.protocol === "rclone" ? "remote name (gdrive)" : "host"}
            value={r.host}
            onChange={(e) => update(i, { host: e.target.value })}
          />
          <input
            type="text"
            aria-label={`Remote target ${i + 1} path`}
            placeholder="remote path (/Backups)"
            value={r.remotePath}
            onChange={(e) => update(i, { remotePath: e.target.value })}
          />
          {r.protocol === "smb" ? (
            <input
              type="text"
              aria-label={`Remote target ${i + 1} share`}
              placeholder="share"
              value={r.share}
              onChange={(e) => update(i, { share: e.target.value })}
            />
          ) : null}
          {r.protocol !== "rclone" ? (
            <>
              <input
                type="text"
                aria-label={`Remote target ${i + 1} username`}
                placeholder="username"
                value={r.username}
                onChange={(e) => update(i, { username: e.target.value })}
              />
              <input
                type="text"
                aria-label={`Remote target ${i + 1} password secret ref`}
                placeholder="password secret ref"
                value={r.passwordRef}
                onChange={(e) => update(i, { passwordRef: e.target.value })}
              />
            </>
          ) : null}
          <button
            type="button"
            className="fathom-btn"
            onClick={() => onChange(rows.filter((_, j) => j !== i))}
          >
            Remove
          </button>
        </div>
      ))}
      <button
        type="button"
        className="fathom-btn"
        onClick={() => onChange([...rows, blankRemoteTarget()])}
      >
        + Add remote target
      </button>
      <p className="fathom-muted">
        rclone auth lives in the host&rsquo;s <code>rclone.conf</code> (and needs an rclone-equipped
        agent image); SMB/SFTP credentials are <strong>secret references</strong> resolved on the
        agent — never typed here.
      </p>
    </fieldset>
  );
}

export function Deploy(): JSX.Element {
  const me = useWhoAmI();
  const canDeploy = principalHas(me.data, "deploy_agent");

  const [mode, setMode] = useState<Mode>("push");
  const [form, setForm] = useState<HostForm>(emptyForm);
  const [batch, setBatch] = useState<DeployHostIn[]>([]);
  const [preflight, setPreflight] = useState<PreflightOut | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [enroll, setEnroll] = useState<EnrollOut | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [pending, setPending] = useState<"deploy" | "enroll" | null>(null);

  // pull form
  const [pullHostId, setPullHostId] = useState("");
  const [pullCoreUrl, setPullCoreUrl] = useState("");

  const preflightM = usePreflight();
  const deployM = useDeployAgents();
  const enrollM = useEnrollToken();
  const mfa = useMfaVerify();
  const run = useDeployRun(runId);
  const deployBrowse = useDeployBrowse();
  const [showTargetTree, setShowTargetTree] = useState(false);

  if (!canDeploy) {
    return (
      <section className="fathom-page" aria-labelledby="deploy-title">
        <header className="fathom-page-head">
          <h1 id="deploy-title">Deploy agents</h1>
        </header>
        <p role="alert" className="fathom-inline-error">
          Deploying agents requires the deploy_agent capability (admin only).
        </p>
      </section>
    );
  }

  const set = <K extends keyof HostForm>(key: K, value: HostForm[K]): void =>
    setForm((f) => ({ ...f, [key]: value }));

  // Switching tabs must drop a half-finished MFA step-up for the *other* mode, or submitting the
  // TOTP would fire the action you navigated away from (round-3 P2).
  const switchMode = (m: Mode): void => {
    setMode(m);
    setPending(null);
    setError(null);
    setMfaCode("");
  };

  // Changing the target invalidates a host-key pinned from a previous preflight.
  const setTarget = (value: string): void =>
    setForm((f) => ({ ...f, target: value, expectedHostKey: "" }));

  const doPreflight = async (): Promise<void> => {
    setError(null);
    setPreflight(null);
    try {
      const host = buildHost(form);
      setPreflight(
        await preflightM.mutateAsync({
          target: host.target,
          port: host.port,
          credential: host.credential,
          proxy_host_ip: host.proxy_host_ip,
          expected_host_key: host.expected_host_key,
        }),
      );
    } catch (e) {
      setError(errorText(e, "Preflight failed."));
    }
  };

  // Password auth sends the password during the SSH handshake; the server rejects it without a
  // pinned host key (T-1). Mirror that here so the operator pins via preflight first.
  const needsPin = form.authMethod === "password" && !form.expectedHostKey.trim();

  const addToBatch = (): void => {
    setError(null);
    if (!form.target.trim() || !form.hostId.trim()) {
      setError("Target and host id are required.");
      return;
    }
    if (needsPin) {
      setError("Password auth requires a pinned host key — run Preflight and pin the key first.");
      return;
    }
    setBatch((b) => [...b, buildHost(form)]);
    setForm(emptyForm());
    setPreflight(null);
  };

  const doDeploy = async (): Promise<void> => {
    setError(null);
    const hosts = batch.length > 0 ? batch : [buildHost(form)];
    try {
      const r = await deployM.mutateAsync({ hosts });
      setRunId(r.run_id);
      setPending(null);
      setMfaCode("");
      // Drop the SSH secrets (key/password/sudo) from component state once dispatched, and clear
      // the batch so a stray re-click can't silently re-deploy the same hosts (round-3 P2).
      setBatch([]);
      setForm(emptyForm());
      setPreflight(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setPending("deploy");
        return;
      }
      setError(errorText(e, "Deploy failed."));
    }
  };

  const doEnroll = async (): Promise<void> => {
    setError(null);
    try {
      const remote = buildRemoteTargets(form.remoteTargets);
      const r = await enrollM.mutateAsync({
        host_id: pullHostId.trim(),
        core_base_url: pullCoreUrl.trim() || undefined,
        remote_targets: remote.length ? remote : undefined,
      });
      setEnroll(r);
      setPending(null);
      setMfaCode("");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setPending("enroll");
        return;
      }
      setError(errorText(e, "Enrolment failed."));
    }
  };

  const doVerifyMfa = async (): Promise<void> => {
    setError(null);
    try {
      await mfa.mutateAsync(mfaCode.trim());
      if (pending === "deploy") await doDeploy();
      else if (pending === "enroll") await doEnroll();
    } catch (e) {
      setError(errorText(e, "Invalid code. Enrol TOTP in Settings if you have not yet."));
    }
  };

  return (
    <section className="fathom-page" aria-labelledby="deploy-title">
      <header className="fathom-page-head">
        <h1 id="deploy-title">Deploy agents</h1>
        <p className="fathom-muted">
          Bring a host into the fleet. <strong>Push</strong> connects out over SSH and installs it
          for you; <strong>Pull</strong> gives you a one-time command to run on the box (no
          credentials leave your hands). The agent&rsquo;s mTLS cert is minted automatically.
        </p>
      </header>

      <div className="fathom-tabs" role="tablist" aria-label="Deploy mode">
        <button
          type="button"
          role="tab"
          aria-selected={mode === "push"}
          className={mode === "push" ? "fathom-btn fathom-btn-primary" : "fathom-btn"}
          onClick={() => switchMode("push")}
        >
          Push (SSH from core)
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === "pull"}
          className={mode === "pull" ? "fathom-btn fathom-btn-primary" : "fathom-btn"}
          onClick={() => switchMode("pull")}
        >
          Pull (paste a command)
        </button>
      </div>

      {error ? (
        <p role="alert" className="fathom-inline-error">
          {error}
        </p>
      ) : null}

      {pending ? (
        <form
          className="fathom-form-inline fathom-card"
          onSubmit={(e) => {
            e.preventDefault();
            void doVerifyMfa();
          }}
        >
          <p className="fathom-muted">Step-up MFA is required before this action.</p>
          <label className="fathom-inline-field">
            TOTP code
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              minLength={6}
              maxLength={8}
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              required
            />
          </label>
          <button type="submit" className="fathom-btn fathom-btn-primary" disabled={mfa.isPending}>
            {mfa.isPending ? "Verifying…" : "Verify & continue"}
          </button>
        </form>
      ) : null}

      {mode === "push" ? (
        <>
          <div className="fathom-card">
            <h2>Host</h2>
            <div className="fathom-form-grid">
              <label className="fathom-inline-field">
                Target (FQDN / IP)
                <input
                  type="text"
                  value={form.target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="203.0.113.20"
                />
              </label>
              <label className="fathom-inline-field">
                Host id (Fathom name)
                <input
                  type="text"
                  value={form.hostId}
                  onChange={(e) => set("hostId", e.target.value)}
                  placeholder="nas-1"
                />
              </label>
              <label className="fathom-inline-field">
                SSH port
                <input
                  type="number"
                  value={form.port}
                  onChange={(e) => set("port", e.target.value)}
                />
              </label>
              <label className="fathom-inline-field">
                SSH user
                <input
                  type="text"
                  value={form.username}
                  onChange={(e) => set("username", e.target.value)}
                />
              </label>
            </div>

            <fieldset className="fathom-form-grid">
              <legend>Authentication</legend>
              <label className="fathom-inline-field">
                Method
                <select
                  value={form.authMethod}
                  onChange={(e) => set("authMethod", e.target.value as AuthMethod)}
                >
                  <option value="key">SSH key (+ optional passphrase / cert)</option>
                  <option value="password">Username + password</option>
                </select>
              </label>
              {form.authMethod === "key" ? (
                <>
                  <label className="fathom-inline-field fathom-field-wide">
                    Private key (PEM)
                    <textarea
                      rows={4}
                      value={form.privateKey}
                      onChange={(e) => set("privateKey", e.target.value)}
                      placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    />
                  </label>
                  <label className="fathom-inline-field">
                    Key passphrase (optional)
                    <input
                      type="password"
                      autoComplete="off"
                      value={form.passphrase}
                      onChange={(e) => set("passphrase", e.target.value)}
                    />
                  </label>
                  <label className="fathom-inline-field fathom-field-wide">
                    SSH certificate (optional — CA-signed user cert for the key)
                    <textarea
                      rows={3}
                      value={form.certificate}
                      onChange={(e) => set("certificate", e.target.value)}
                      placeholder="ssh-ed25519-cert-v01@openssh.com …"
                    />
                  </label>
                </>
              ) : (
                <label className="fathom-inline-field">
                  SSH password
                  <input
                    type="password"
                    autoComplete="off"
                    value={form.password}
                    onChange={(e) => set("password", e.target.value)}
                  />
                </label>
              )}
              <label className="fathom-inline-field">
                Sudo password (optional)
                <input
                  type="password"
                  autoComplete="off"
                  value={form.sudoPassword}
                  onChange={(e) => set("sudoPassword", e.target.value)}
                  placeholder="blank = passwordless sudo"
                />
              </label>
            </fieldset>

            <fieldset className="fathom-form-grid">
              <legend>Scan scope &amp; proxy</legend>
              <label className="fathom-inline-field">
                Host path
                <input
                  type="text"
                  value={form.hostPath}
                  onChange={(e) =>
                    setForm((f) => ({
                      ...f,
                      hostPath: e.target.value,
                      containerPath: deriveAgentPath(e.target.value),
                    }))
                  }
                />
              </label>
              <label className="fathom-inline-field">
                Agent path <span className="fathom-muted fathom-hint">(auto-filled)</span>
                <input
                  type="text"
                  value={form.containerPath}
                  onChange={(e) => set("containerPath", e.target.value)}
                />
              </label>
              <label className="fathom-inline-field">
                Proxy host IP (mTLS terminator the agent reaches; empty = server default)
                <input
                  type="text"
                  value={form.proxyHostIp}
                  onChange={(e) => set("proxyHostIp", e.target.value)}
                  placeholder="203.0.113.10"
                />
              </label>
              {form.target.trim() && form.username.trim() ? (
                <div className="fathom-field-wide">
                  <div className="fathom-tree-controls">
                    <button
                      type="button"
                      className="fathom-btn fathom-btn-mini"
                      aria-expanded={showTargetTree}
                      onClick={() => setShowTargetTree((v) => !v)}
                    >
                      {showTargetTree ? "Hide explorer" : "Explore target…"}
                    </button>
                    <span className="fathom-muted fathom-hint">
                      Browse the target&rsquo;s real folders (live over SSH) to pick the host path.
                    </span>
                  </div>
                  {showTargetTree ? (
                    <div className="fathom-tree-wrap">
                      <DirTree
                        roots={[{ path: "/", label: "/" }]}
                        includeLabel="use as host path"
                        browse={(path) =>
                          deployBrowse.mutateAsync({
                            target: form.target.trim(),
                            port: Number(form.port) || 22,
                            credential: buildCredential(form),
                            proxy_host_ip: form.proxyHostIp.trim() || undefined,
                            expected_host_key: form.expectedHostKey.trim() || null,
                            path,
                          })
                        }
                        onInclude={(path) =>
                          setForm((f) => ({
                            ...f,
                            hostPath: path,
                            containerPath: deriveAgentPath(path),
                          }))
                        }
                      />
                    </div>
                  ) : null}
                </div>
              ) : null}
            </fieldset>

            <RemoteTargetsEditor
              rows={form.remoteTargets}
              onChange={(r) => set("remoteTargets", r)}
            />

            <footer className="fathom-modal-foot">
              <button
                type="button"
                className="fathom-btn"
                disabled={preflightM.isPending || !form.target.trim()}
                onClick={() => void doPreflight()}
              >
                {preflightM.isPending ? "Checking…" : "Preflight"}
              </button>
              <button type="button" className="fathom-btn" onClick={addToBatch}>
                Add to batch
              </button>
              <button
                type="button"
                className="fathom-btn fathom-btn-primary"
                disabled={
                  deployM.isPending ||
                  (batch.length === 0 && (!form.target.trim() || needsPin))
                }
                title={needsPin && batch.length === 0 ? "Pin the host key first (password auth)" : undefined}
                onClick={() => void doDeploy()}
              >
                {deployM.isPending
                  ? "Deploying…"
                  : batch.length > 0
                    ? `Deploy ${batch.length} host(s)`
                    : "Deploy this host"}
              </button>
            </footer>

            {preflight ? (
              <>
                <p
                  role="status"
                  className={preflight.ok ? "fathom-inline-ok" : "fathom-inline-error"}
                >
                  {preflight.ok
                    ? "Reachable — docker present, proxy reachable."
                    : `Not ready: ${preflight.notes.join("; ") || "see checks"}.`}
                </p>
                {preflight.host_key_fingerprint ? (
                  <p className="fathom-muted">
                    Host key: <code className="fathom-path">{preflight.host_key_fingerprint}</code>{" "}
                    {form.expectedHostKey === preflight.host_key_fingerprint ? (
                      <strong>✓ pinned — deploy aborts if it changes</strong>
                    ) : (
                      <button
                        type="button"
                        className="fathom-btn"
                        onClick={() => set("expectedHostKey", preflight.host_key_fingerprint)}
                      >
                        Pin this key for deploy
                      </button>
                    )}
                  </p>
                ) : null}
              </>
            ) : null}
          </div>

          {batch.length > 0 ? (
            <div className="fathom-card">
              <h2>Batch ({batch.length})</h2>
              <table className="fathom-table">
                <thead>
                  <tr>
                    <th>Host id</th>
                    <th>Target</th>
                    <th>Auth</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {batch.map((h, i) => (
                    <tr key={`${h.host_id}-${i}`}>
                      <td>{h.host_id}</td>
                      <td>{h.target}</td>
                      <td>{h.credential.private_key ? "key" : "password"}</td>
                      <td>
                        <button
                          type="button"
                          className="fathom-btn"
                          onClick={() => setBatch((b) => b.filter((_, j) => j !== i))}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}

          {run.data ? (
            <div className="fathom-card">
              <h2>
                Deploy run {run.data.run_id} {run.data.complete ? "✓" : "…"}
              </h2>
              <table className="fathom-table">
                <thead>
                  <tr>
                    <th>Host id</th>
                    <th>Target</th>
                    <th>Phase</th>
                    <th>Detail</th>
                    <th>Fingerprint</th>
                  </tr>
                </thead>
                <tbody>
                  {run.data.hosts.map((h) => (
                    <tr key={h.host_id}>
                      <td>{h.host_id}</td>
                      <td>{h.target}</td>
                      <td>{h.phase}</td>
                      <td>{h.detail}</td>
                      <td className="fathom-path">{h.fingerprint ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </>
      ) : (
        <div className="fathom-card">
          <h2>Pull enrolment</h2>
          <p className="fathom-muted">
            Generates a one-time command (valid briefly, single-use). Run it on the target; it
            fetches its bundle and starts the agent. The image must already be on the host.
          </p>
          <div className="fathom-form-grid">
            <label className="fathom-inline-field">
              Host id (Fathom name)
              <input
                type="text"
                value={pullHostId}
                onChange={(e) => setPullHostId(e.target.value)}
                placeholder="nas-1"
              />
            </label>
            <label className="fathom-inline-field fathom-field-wide">
              Core base URL (reachable from the target; empty = server default)
              <input
                type="text"
                value={pullCoreUrl}
                onChange={(e) => setPullCoreUrl(e.target.value)}
                placeholder="https://core.example.com:18088"
              />
            </label>
          </div>
          <RemoteTargetsEditor
            rows={form.remoteTargets}
            onChange={(r) => set("remoteTargets", r)}
          />
          <footer className="fathom-modal-foot">
            <button
              type="button"
              className="fathom-btn fathom-btn-primary"
              disabled={enrollM.isPending || !pullHostId.trim()}
              onClick={() => void doEnroll()}
            >
              {enrollM.isPending ? "Generating…" : "Generate command"}
            </button>
          </footer>
          {pullCoreUrl.trim().startsWith("http://") ? (
            <p role="alert" className="fathom-inline-error">
              Core URL is plain HTTP — the bundle (with the agent&rsquo;s private key) and the
              one-time token transit in cleartext. Front it with HTTPS for a real deploy.
            </p>
          ) : null}
          {enroll ? (
            <>
              <p className="fathom-muted">
                Run this on <strong>{enroll.host_id}</strong> (expires {enroll.expires_at}):
              </p>
              <pre className="fathom-code-block">
                <code>{enroll.command}</code>
              </pre>
              <button
                type="button"
                className="fathom-btn"
                onClick={() => {
                  // navigator.clipboard is undefined in an insecure (http) context — guard it so the
                  // handler never throws (round-2 P3); fall back to selecting the command text.
                  if (navigator.clipboard) {
                    void navigator.clipboard.writeText(enroll.command).catch(() => undefined);
                  } else {
                    setError("Copy unavailable over http — select the command above to copy it.");
                  }
                }}
              >
                Copy command
              </button>
            </>
          ) : null}
        </div>
      )}
    </section>
  );
}
