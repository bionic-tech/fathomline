// Settings (frontend ADD §4): the current principal + (admin-only) user / role-assignment
// management over the admin_users API (ADD 13 §§1-3, §8). The "your account" panel renders for
// every authenticated user; the user-management panel is gated on MANAGE_USERS (admin) and
// hidden otherwise — the server stays authoritative (every grant/revoke is audited there).

import { Fragment, useState } from "react";
import { QRCodeSVG } from "qrcode.react";

import { ApiError } from "../../api/client";
import {
  useAdminUsers,
  useCreateAssignment,
  useCreateUser,
  useDeleteAssignment,
  useMfaEnroll,
  useMfaVerify,
  useServerConfig,
  useUserAssignments,
  useVolumes,
  useWhoAmI,
} from "../../api/queries";
import { principalHas, type Role } from "../../auth/rbac";
import type { AdminUserOut, CreateAssignmentRequest } from "../../api/types";
import { QueryState } from "../common/QueryState";
import { Tabs, type TabDef } from "../common/Tabs";
import { RerunSetupControl } from "../onboarding/RerunSetupControl";
import { RuntimeSettings } from "./RuntimeSettings";

const ROLES: Role[] = ["viewer", "operator", "remediator", "auditor", "admin"];
const SCOPE_KINDS: CreateAssignmentRequest["scope_kind"][] = ["global", "host", "volume"];

function MyAccount(): JSX.Element {
  const me = useWhoAmI();
  return (
    <section aria-label="Your account" className="fathom-card">
      <h2 className="fathom-card-title">Your account</h2>
      <QueryState isLoading={me.isLoading} isError={me.isError} error={me.error}>
        {me.data ? (
          <dl className="fathom-keyvals">
            <dt>Subject</dt>
            <dd>{me.data.subject}</dd>
            <dt>Display name</dt>
            <dd>{me.data.display_name ?? "—"}</dd>
            <dt>Source</dt>
            <dd>{me.data.source}</dd>
            <dt>Groups</dt>
            <dd>{me.data.groups.length ? me.data.groups.join(", ") : "—"}</dd>
            <dt>MFA</dt>
            <dd>{me.data.mfa_fresh ? "fresh (step-up valid)" : "not fresh"}</dd>
            <dt>Grants</dt>
            <dd>
              {me.data.grants.length === 0 ? (
                "—"
              ) : (
                <ul className="fathom-grant-list">
                  {me.data.grants.map((g, i) => (
                    <li key={i}>
                      <span className="fathom-badge fathom-badge-role">{g.role}</span> {g.scope_kind}
                      {g.host_id != null ? ` host:${g.host_id}` : ""}
                      {g.volume_id != null ? ` vol:${g.volume_id}` : ""}
                    </li>
                  ))}
                </ul>
              )}
            </dd>
          </dl>
        ) : null}
      </QueryState>
    </section>
  );
}

// Per-user TOTP enrolment (any authenticated user). Enrol → scan a QR code (or enter the secret by
// hand) in an authenticator app → confirm with a 6-digit code. MFA is required to reveal stored
// secrets and for destructive actions (remediation, agent deploy). The QR is rendered LOCALLY from
// the otpauth URI (qrcode.react, in-browser) — the secret is never sent to any external QR service,
// preserving the original no-leak posture while still letting the phone scan it.
function MfaSetup(): JSX.Element {
  const me = useWhoAmI();
  const enroll = useMfaEnroll();
  const verify = useMfaVerify();
  const [uri, setUri] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [done, setDone] = useState(false);

  const enrolled = me.data?.mfa_enrolled ?? false;
  const secret = uri ? new URLSearchParams(uri.split("?")[1] ?? "").get("secret") : null;

  const begin = (): void => {
    setDone(false);
    enroll.mutate(undefined, {
      onSuccess: (d) => {
        setUri(d.provisioning_uri);
        setCode("");
      },
    });
  };
  const confirm = (e: React.FormEvent): void => {
    e.preventDefault();
    verify.mutate(code.trim(), {
      onSuccess: () => {
        setDone(true);
        setUri(null);
        setCode("");
      },
    });
  };
  const copy = (text: string): void => {
    void navigator.clipboard?.writeText(text);
  };

  return (
    <section aria-label="Multi-factor authentication" className="fathom-card">
      <h2 className="fathom-card-title">Multi-factor authentication</h2>
      <p className="fathom-muted">
        A time-based one-time code (TOTP) from an authenticator app. Required to reveal stored
        secrets and for destructive actions (remediation, agent deploy).
      </p>
      <p>
        Status:{" "}
        {enrolled ? (
          <span className="fathom-badge fathom-badge-success">enabled</span>
        ) : (
          <span className="fathom-badge fathom-badge-neutral">not set up</span>
        )}
        {done ? (
          <span role="status" className="fathom-inline-ok">
            {" "}
            MFA enabled.
          </span>
        ) : null}
      </p>

      {uri == null ? (
        <button
          type="button"
          className="fathom-btn fathom-btn-primary"
          disabled={enroll.isPending}
          onClick={begin}
        >
          {enroll.isPending ? "Starting…" : enrolled ? "Re-enrol authenticator" : "Set up MFA"}
        </button>
      ) : (
        <div className="fathom-mfa-setup">
          <ol className="fathom-steps">
            <li>
              Open your authenticator app (Google Authenticator, Authy, 1Password…), add a new
              account, and scan this QR code:
              <div className="fathom-qr">
                <QRCodeSVG value={uri} size={180} marginSize={2} aria-label="MFA enrolment QR code" />
              </div>
            </li>
            <li>
              <details className="fathom-advanced">
                <summary>Can&apos;t scan? Enter the secret by hand</summary>
                <div className="fathom-form-inline">
                  <code className="fathom-revealed">{secret}</code>
                  <button type="button" className="fathom-btn" onClick={() => copy(secret ?? "")}>
                    Copy secret
                  </button>
                </div>
                <div className="fathom-form-inline">
                  <code className="fathom-path">{uri}</code>
                  <button type="button" className="fathom-btn" onClick={() => copy(uri)}>
                    Copy otpauth URI
                  </button>
                </div>
              </details>
            </li>
            <li>Enter the 6-digit code it shows to confirm:</li>
          </ol>
          <form className="fathom-form-inline" onSubmit={confirm} aria-label="Confirm MFA code">
            <label className="fathom-inline-field">
              Code
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                minLength={6}
                maxLength={8}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
              />
            </label>
            <button
              type="submit"
              className="fathom-btn fathom-btn-primary"
              disabled={verify.isPending || code.trim().length < 6}
            >
              {verify.isPending ? "Verifying…" : "Verify & enable"}
            </button>
            <button
              type="button"
              className="fathom-btn"
              onClick={() => {
                setUri(null);
                setCode("");
              }}
            >
              Cancel
            </button>
          </form>
          {verify.isError ? (
            <p role="alert" className="fathom-inline-error">
              Invalid code — check your device clock and enter the current code.
            </p>
          ) : null}
        </div>
      )}
      {enroll.isError ? (
        <p role="alert" className="fathom-inline-error">
          Could not start enrolment.
        </p>
      ) : null}
    </section>
  );
}

function AssignmentEditor({ user }: { user: AdminUserOut }): JSX.Element {
  const assignments = useUserAssignments(user.id);
  const volumes = useVolumes();
  const create = useCreateAssignment();
  const remove = useDeleteAssignment();
  const [role, setRole] = useState<Role>("viewer");
  const [scopeKind, setScopeKind] = useState<CreateAssignmentRequest["scope_kind"]>("global");
  const [volumeId, setVolumeId] = useState<number | "">("");
  const [hostId, setHostId] = useState<number | "">("");

  const onGrant = (e: React.FormEvent): void => {
    e.preventDefault();
    const body: CreateAssignmentRequest = {
      role,
      scope_kind: scopeKind,
      host_id: scopeKind === "host" ? (hostId === "" ? null : Number(hostId)) : null,
      volume_id: scopeKind === "volume" ? (volumeId === "" ? null : Number(volumeId)) : null,
    };
    create.mutate({ userId: user.id, body });
  };

  return (
    <td colSpan={4} className="fathom-detail-cell">
      <QueryState
        isLoading={assignments.isLoading}
        isError={assignments.isError}
        error={assignments.error}
        isEmpty={(assignments.data?.length ?? 0) === 0}
        emptyLabel="No role assignments."
      >
        <ul className="fathom-assignment-list">
          {(assignments.data ?? []).map((a) => (
            <li key={a.id}>
              <span className="fathom-badge fathom-badge-role">{a.role}</span> {a.scope_kind}
              {a.host_id != null ? ` host:${a.host_id}` : ""}
              {a.volume_id != null ? ` vol:${a.volume_id}` : ""}
              <button
                type="button"
                className="fathom-btn fathom-btn-danger"
                disabled={remove.isPending}
                onClick={() => remove.mutate({ userId: user.id, assignmentId: a.id })}
              >
                Revoke
              </button>
            </li>
          ))}
        </ul>
      </QueryState>

      <form className="fathom-form fathom-form-inline" onSubmit={onGrant} aria-label="Grant role">
        <label className="fathom-field">
          Role
          <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
        <label className="fathom-field">
          Scope
          <select
            value={scopeKind}
            onChange={(e) =>
              setScopeKind(e.target.value as CreateAssignmentRequest["scope_kind"])
            }
          >
            {SCOPE_KINDS.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        {scopeKind === "volume" ? (
          <label className="fathom-field">
            Volume
            <select
              value={volumeId}
              onChange={(e) => setVolumeId(e.target.value === "" ? "" : Number(e.target.value))}
            >
              <option value="">— select —</option>
              {(volumes.data ?? []).map((v) => (
                <option key={v.id} value={v.id}>
                  {v.mountpoint}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        {scopeKind === "host" ? (
          <label className="fathom-field">
            Host id
            <input
              type="number"
              min={1}
              value={hostId}
              onChange={(e) => setHostId(e.target.value === "" ? "" : Number(e.target.value))}
            />
          </label>
        ) : null}
        <button
          type="submit"
          className="fathom-btn fathom-btn-primary"
          disabled={create.isPending}
        >
          Grant
        </button>
        {create.isError ? (
          <span role="alert" className="fathom-inline-error">
            {create.error instanceof ApiError
              ? (create.error.problem.detail ?? "Grant failed.")
              : "Grant failed."}
          </span>
        ) : null}
      </form>
    </td>
  );
}

function UserManagement(): JSX.Element {
  const me = useWhoAmI();
  const canManageUsers = principalHas(me.data, "manage_users");
  const users = useAdminUsers(true);
  const create = useCreateUser();
  const [openUser, setOpenUser] = useState<number | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const onCreate = (e: React.FormEvent): void => {
    e.preventDefault();
    create.mutate(
      { username: username.trim(), password },
      {
        onSuccess: () => {
          setUsername("");
          setPassword("");
        },
      },
    );
  };

  return (
    <section aria-label="User management" className="fathom-card">
      <h2 className="fathom-card-title">Users &amp; roles</h2>

      {canManageUsers ? (
        <form
          className="fathom-form fathom-form-inline"
          onSubmit={onCreate}
          aria-label="Create user"
        >
          <label className="fathom-field">
            Username
            <input
              type="text"
              autoComplete="off"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </label>
          <label className="fathom-field">
            Password
            <input
              type="password"
              autoComplete="new-password"
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          <button
            type="submit"
            className="fathom-btn fathom-btn-primary"
            disabled={create.isPending || username.trim() === "" || password.length < 8}
          >
            {create.isPending ? "Creating…" : "Create user"}
          </button>
          {create.isError ? (
            <span role="alert" className="fathom-inline-error">
              {create.error instanceof ApiError && create.error.status === 409
                ? "User already exists."
                : create.error instanceof ApiError
                  ? (create.error.problem.detail ?? "Could not create user.")
                  : "Could not create user."}
            </span>
          ) : null}
        </form>
      ) : null}

      <QueryState
        isLoading={users.isLoading}
        isError={users.isError}
        error={users.error}
        isEmpty={(users.data?.length ?? 0) === 0}
        emptyLabel="No users."
      >
        <table className="fathom-table">
          <caption className="sr-only">Users and their role assignments</caption>
          <thead>
            <tr>
              <th scope="col">User</th>
              <th scope="col">Source</th>
              <th scope="col">Active</th>
              <th scope="col">Assignments</th>
            </tr>
          </thead>
          <tbody>
            {(users.data ?? []).map((u) => (
              <Fragment key={u.id}>
                <tr>
                  <td>{u.display_name ? `${u.display_name} (${u.subject})` : u.subject}</td>
                  <td>{u.source}</td>
                  <td>{u.is_active ? "yes" : "no"}</td>
                  <td>
                    <button
                      type="button"
                      className="fathom-disclosure"
                      aria-expanded={openUser === u.id}
                      onClick={() => setOpenUser((cur) => (cur === u.id ? null : u.id))}
                    >
                      {openUser === u.id ? "Hide" : "Manage"}
                    </button>
                  </td>
                </tr>
                {openUser === u.id ? (
                  <tr>
                    <AssignmentEditor user={u} />
                  </tr>
                ) : null}
              </Fragment>
            ))}
          </tbody>
        </table>
      </QueryState>
    </section>
  );
}

function onOff(v: boolean): JSX.Element {
  return (
    <span className={`fathom-badge ${v ? "fathom-badge-online" : "fathom-badge-offline"}`}>
      {v ? "on" : "off"}
    </span>
  );
}

// Read-only view of the server's feature gates. These are env-controlled (not UI-editable) by
// design — flipping "let the app move/delete files" from a browser would be the wrong trust
// boundary — so this panel just SHOWS them, greyed, with where to change them.
function ServerConfig(): JSX.Element {
  const cfg = useServerConfig();
  return (
    <section aria-label="Server configuration" className="fathom-card fathom-config-card">
      <h2 className="fathom-card-title">Server configuration</h2>
      <p className="fathom-muted">
        Feature gates are set by <strong>environment variables</strong> in the server&apos;s{" "}
        <code>.env</code> (not editable here, by design). This is the live, read-only view.
      </p>
      <QueryState isLoading={cfg.isLoading} isError={cfg.isError} error={cfg.error}>
        {cfg.data ? (
          <dl className="fathom-keyvals fathom-config-grid">
            <dt>Organize (AI) enabled</dt>
            <dd>{onOff(cfg.data.organize_enabled)}</dd>
            <dt>Inference provider</dt>
            <dd>
              <code>{cfg.data.inference_provider}</code>
            </dd>
            <dt>Inference model</dt>
            <dd>
              <code>{cfg.data.inference_model}</code>
            </dd>
            <dt>Inference URL</dt>
            <dd className="fathom-path">{cfg.data.inference_ollama_url}</dd>
            <dt>Organize model override</dt>
            <dd>
              <code>{cfg.data.organize_model ?? "(uses inference model)"}</code>
            </dd>
            <dt>Cloud inference egress</dt>
            <dd>{onOff(cfg.data.inference_allow_egress)}</dd>
            <dt>Inference timeout</dt>
            <dd className="tabular-nums">{cfg.data.inference_timeout_seconds}s</dd>
            <dt>Remediation (write) enabled</dt>
            <dd>{onOff(cfg.data.remediation_enabled)}</dd>
            <dt>Remediation blast cap</dt>
            <dd className="tabular-nums">{cfg.data.remediation_blast_cap}</dd>
            <dt>Preview (sandbox) enabled</dt>
            <dd>{onOff(cfg.data.preview_enabled)}</dd>
            <dt>Change-log retention</dt>
            <dd className="tabular-nums">{cfg.data.change_log_retention_days} days</dd>
          </dl>
        ) : null}
      </QueryState>
    </section>
  );
}

export function Settings(): JSX.Element {
  const me = useWhoAmI();
  const canManageUsers = principalHas(me.data, "manage_users");
  const canManageSettings = principalHas(me.data, "manage_settings");

  const tabs: TabDef[] = [
    {
      id: "account",
      label: "Account",
      content: (
        <>
          <MyAccount />
          <MfaSetup />
        </>
      ),
    },
    {
      id: "config",
      label: "Configuration",
      content: canManageSettings ? (
        <>
          <RuntimeSettings />
          <RerunSetupControl />
        </>
      ) : (
        <ServerConfig />
      ),
    },
  ];
  if (canManageUsers) {
    tabs.push({ id: "users", label: "Users & roles", content: <UserManagement /> });
  }

  return (
    <section aria-labelledby="settings-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="settings-title">Settings</h1>
        <p className="fathom-muted">
          Your account, the server&apos;s feature configuration, and (for admins) runtime settings,
          user and role management.
        </p>
      </header>

      <Tabs tabs={tabs} ariaLabel="Settings sections" />
    </section>
  );
}
