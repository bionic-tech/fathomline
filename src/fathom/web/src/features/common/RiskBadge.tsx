// A small colored risk label derived from a path (riskClass.ts): OS = red, service data = orange,
// config/compose = yellow. Renders nothing for ordinary user data, so it only ever draws attention
// to paths where a delete/dedup deserves caution.

import { riskFor } from "../../lib/riskClass";

export function RiskBadge({ path, name }: { path: string; name?: string }): JSX.Element | null {
  const meta = riskFor(path, name);
  if (!meta) return null;
  return (
    <span className={`fathom-badge ${meta.badge}`} title={meta.caution ?? undefined}>
      {meta.label}
    </span>
  );
}
