// Duplicates (frontend ADD §4, fullbit-dedup): the dedup report. Lists confirmed duplicate groups
// (keyset-paginated, scope-filtered server-side) with reclaimable bytes and a non-binding
// suggested keeper; expanding a group lazily loads its in-scope members. The view stays
// report-first; the gated, MFA-protected write action (RemediationWizard, ADR-011) is offered as a
// per-group "Reclaim" button only to principals with BUILD_REMEDIATION.

import { useState } from "react";

import {
  useDuplicateGroup,
  useDuplicates,
  useProviderDuplicates,
  useVolumes,
  useWhoAmI,
} from "../../api/queries";
import { principalHas } from "../../auth/rbac";
import type { DuplicateGroupOut, ProviderDuplicateGroupOut } from "../../api/types";
import { displayPath, formatBytes, formatBytesExact } from "../../lib/format";
import { useNames } from "../../lib/names";
import { useUiStore } from "../../state/uiStore";
import { QueryState } from "../common/QueryState";
import { RemediationWizard } from "../remediation/RemediationWizard";

function GroupMembers({ groupId }: { groupId: number }): JSX.Element {
  const detail = useDuplicateGroup(groupId);
  const { hostName, volumeLabel } = useNames();
  return (
    <QueryState
      isLoading={detail.isLoading}
      isError={detail.isError}
      error={detail.error}
      isEmpty={(detail.data?.members.length ?? 0) === 0}
      emptyLabel="No in-scope members."
    >
      <table className="fathom-table">
        <caption className="sr-only">Members of duplicate group {groupId}</caption>
        <thead>
          <tr>
            <th scope="col">Path</th>
            <th scope="col">Host</th>
            <th scope="col">Volume</th>
            <th scope="col">Keeper</th>
          </tr>
        </thead>
        <tbody>
          {(detail.data?.members ?? []).map((m) => (
            <tr key={m.entry_id} className={m.is_mount_alias ? "fathom-muted" : undefined}>
              <td className="fathom-path" title={m.path}>{displayPath(m.path)}</td>
              <td>{hostName(m.host_id)}</td>
              <td>{volumeLabel(m.volume_id)}</td>
              <td>
                {m.is_mount_alias ? (
                  <span
                    className="fathom-badge fathom-badge-flag"
                    title="On a network mount (NFS/SMB) — the same physical file seen via a remote mount, not a reclaimable copy. Excluded from reclaimable space."
                  >
                    mount alias
                  </span>
                ) : detail.data?.suggested_keeper_entry_id === m.entry_id ? (
                  <span
                    className="fathom-badge fathom-badge-keeper"
                    title={detail.data?.suggested_keeper_reason ?? undefined}
                  >
                    suggested
                  </span>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </QueryState>
  );
}

function GroupRow({
  group,
  canReclaim,
  onReclaim,
}: {
  group: DuplicateGroupOut;
  canReclaim: boolean;
  onReclaim: (g: DuplicateGroupOut) => void;
}): JSX.Element {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr>
        <td>
          <button
            type="button"
            className="fathom-disclosure"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "▾" : "▸"} <span className="fathom-hash">{group.full_hash.slice(0, 12)}…</span>
          </button>
        </td>
        <td className="tabular-nums" title={formatBytesExact(group.size)}>
          {formatBytes(group.size)}
        </td>
        <td className="tabular-nums">{group.member_count}</td>
        <td className="tabular-nums" title={formatBytesExact(group.reclaimable_bytes)}>
          {formatBytes(group.reclaimable_bytes)}
        </td>
        {canReclaim ? (
          <td>
            <button type="button" className="fathom-btn" onClick={() => onReclaim(group)}>
              Reclaim…
            </button>
          </td>
        ) : null}
      </tr>
      {open ? (
        <tr>
          <td colSpan={canReclaim ? 5 : 4} className="fathom-detail-cell">
            <GroupMembers groupId={group.id} />
          </td>
        </tr>
      ) : null}
    </>
  );
}

function ProviderGroupRow({ group }: { group: ProviderDuplicateGroupOut }): JSX.Element {
  const [open, setOpen] = useState(false);
  const { hostName, volumeLabel } = useNames();
  return (
    <>
      <tr>
        <td>
          <button
            type="button"
            className="fathom-disclosure"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "▾" : "▸"}{" "}
            <span className="fathom-badge fathom-badge-metadata">{group.algo}</span>{" "}
            <span className="fathom-hash">{group.provider_hash.slice(0, 12)}…</span>
          </button>
        </td>
        <td className="tabular-nums" title={formatBytesExact(group.size)}>
          {formatBytes(group.size)}
        </td>
        <td className="tabular-nums">{group.member_count}</td>
        <td className="tabular-nums" title={formatBytesExact(group.reclaimable_bytes)}>
          {formatBytes(group.reclaimable_bytes)}
        </td>
      </tr>
      {open ? (
        <tr>
          <td colSpan={4} className="fathom-detail-cell">
            <table className="fathom-table">
              <caption className="sr-only">Members of provider-hash group</caption>
              <thead>
                <tr>
                  <th scope="col">Path</th>
                  <th scope="col">Host</th>
                  <th scope="col">Volume</th>
                </tr>
              </thead>
              <tbody>
                {group.members.map((m) => (
                  <tr key={m.entry_id}>
                    <td className="fathom-path" title={m.path}>{displayPath(m.path)}</td>
                    <td>{hostName(m.host_id)}</td>
                    <td>{volumeLabel(m.volume_id)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function ProviderDuplicatesSection({
  volumeId,
  enabled,
}: {
  volumeId: number | null;
  enabled: boolean;
}): JSX.Element | null {
  const provider = useProviderDuplicates(volumeId, enabled);
  // Only surface the section once there's something to show — it's a cloud-only feature, so most
  // estates without rclone remotes have nothing here and shouldn't see an empty table.
  if (!provider.data || provider.data.items.length === 0) return null;
  return (
    <section aria-labelledby="cloud-dup-title" className="fathom-card" style={{ marginTop: "1.5rem" }}>
      <h2 id="cloud-dup-title">Cross-cloud duplicates</h2>
      <p className="fathom-muted">
        Identical objects per the storage <strong>provider&rsquo;s own hash</strong> (no download).
        Report-only — these never drive a reclaim (that needs a content-verified hash).
        {provider.data.truncated ? " Showing the first results — narrow by volume to see more." : ""}
      </p>
      <table className="fathom-table">
        <caption className="sr-only">Provider-hash duplicate groups</caption>
        <thead>
          <tr>
            <th scope="col">Group (provider hash)</th>
            <th scope="col">Size each</th>
            <th scope="col">Copies</th>
            <th scope="col">Reclaimable</th>
          </tr>
        </thead>
        <tbody>
          {provider.data.items.map((g) => (
            <ProviderGroupRow key={`${g.algo}:${g.provider_hash}:${g.size}`} group={g} />
          ))}
        </tbody>
      </table>
    </section>
  );
}

export function Duplicates(): JSX.Element {
  const me = useWhoAmI();
  const canView = principalHas(me.data, "view_dedup");
  const canReclaim = principalHas(me.data, "build_remediation");
  const volumes = useVolumes();
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const [cursor, setCursor] = useState<string | null>(null);
  const [reclaim, setReclaim] = useState<DuplicateGroupOut | null>(null);
  const dups = useDuplicates(selectedVolumeId, cursor, canView);

  const totalReclaimable = (dups.data?.items ?? []).reduce(
    (sum, g) => sum + g.reclaimable_bytes,
    0,
  );
  const volumeLabel =
    volumes.data?.find((v) => v.id === selectedVolumeId)?.mountpoint ?? "all in-scope volumes";

  if (me.data && !canView) {
    return (
      <section aria-labelledby="dup-title" className="fathom-page">
        <h1 id="dup-title">Duplicates</h1>
        <p className="fathom-muted">You do not have the dedup-report capability.</p>
      </section>
    );
  }

  return (
    <section aria-labelledby="dup-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="dup-title">Duplicates</h1>
        <p className="fathom-muted">
          Dedup report for {volumeLabel}. Reclaimable on this page:{" "}
          <strong className="tabular-nums" title={formatBytesExact(totalReclaimable)}>
            {formatBytes(totalReclaimable)}
          </strong>
          {canReclaim ? " — use Reclaim to quarantine the extra copies (MFA-gated)." : "."}
        </p>
      </header>

      <QueryState
        isLoading={dups.isLoading}
        isError={dups.isError}
        error={dups.error}
        isEmpty={(dups.data?.items.length ?? 0) === 0}
        emptyLabel="No duplicate groups in scope."
      >
        <table className="fathom-table">
          <caption className="sr-only">Duplicate groups with reclaimable bytes</caption>
          <thead>
            <tr>
              <th scope="col">Group (content hash)</th>
              <th scope="col">Size each</th>
              <th scope="col">Copies</th>
              <th scope="col">Reclaimable</th>
              {canReclaim ? <th scope="col">Action</th> : null}
            </tr>
          </thead>
          <tbody>
            {(dups.data?.items ?? []).map((g) => (
              <GroupRow key={g.id} group={g} canReclaim={canReclaim} onReclaim={setReclaim} />
            ))}
          </tbody>
        </table>
      </QueryState>

      {reclaim ? (
        <RemediationWizard group={reclaim} onClose={() => setReclaim(null)} />
      ) : null}

      <div className="fathom-pager">
        <button
          type="button"
          className="fathom-btn"
          disabled={cursor === null}
          onClick={() => setCursor(null)}
        >
          First page
        </button>
        <button
          type="button"
          className="fathom-btn"
          disabled={!dups.data?.next_cursor}
          onClick={() => setCursor(dups.data?.next_cursor ?? null)}
        >
          Next page
        </button>
      </div>

      <ProviderDuplicatesSection volumeId={selectedVolumeId} enabled={canView} />
    </section>
  );
}
