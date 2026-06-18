// Settings (frontend ADD §4): the current principal + (admin-only) user / role-assignment
// management over the admin_users API (ADD 13 §§1-3, §8). The "your account" panel renders for
// every authenticated user; the user-management panel is gated on MANAGE_USERS (admin) and
// hidden otherwise — the server stays authoritative (every grant/revoke is audited there).

import { useState } from "react";

import { ApiError } from "../../api/client";
import {
  useAdminUsers,
  useCreateAssignment,
  useDeleteAssignment,
  useServerConfig,
  useUserAssignments,
  useVolumes,
  useWhoAmI,
} from "../../api/queries";
import { principalHas, type Role } from "../../auth/rbac";
import type { AdminUserOut, CreateAssignmentRequest } from "../../api/types";
import { QueryState } from "../common/QueryState";

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
  const users = useAdminUsers(true);
  const [openUser, setOpenUser] = useState<number | null>(null);

  return (
    <section aria-label="User management" className="fathom-card">
      <h2 className="fathom-card-title">Users &amp; roles</h2>
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
              <>
                <tr key={u.id}>
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
                  <tr key={`${u.id}-detail`}>
                    <AssignmentEditor user={u} />
                  </tr>
                ) : null}
              </>
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
            <dt>Inference URL</dt>
            <dd className="fathom-path">{cfg.data.inference_ollama_url}</dd>
            <dt>Organize model</dt>
            <dd>
              <code>{cfg.data.organize_model}</code>
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

  return (
    <section aria-labelledby="settings-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="settings-title">Settings</h1>
        <p className="fathom-muted">
          Your account, the server&apos;s feature configuration, and (for admins) user and role
          management.
        </p>
      </header>

      <MyAccount />
      <ServerConfig />
      {canManageUsers ? <UserManagement /> : null}
    </section>
  );
}
