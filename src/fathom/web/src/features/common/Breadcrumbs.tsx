// Path breadcrumb (shared by the Dashboard composition view + the Explorer). Renders the trail
// from the volume mountpoint down to the current path; every segment except the last is a button
// that navigates (re-roots the drill query) to that ancestor.

export interface BreadcrumbsProps {
  mount: string;
  path: string;
  onNavigate: (path: string) => void;
}

interface Crumb {
  label: string;
  full: string;
}

function buildCrumbs(mount: string, path: string): Crumb[] {
  const base = mount.replace(/\/+$/, "");
  const rel = path.startsWith(base) ? path.slice(base.length) : path;
  const parts = rel.split("/").filter(Boolean);
  const crumbs: Crumb[] = [{ label: base || "/", full: base || "/" }];
  let cur = base;
  for (const part of parts) {
    cur = `${cur}/${part}`;
    crumbs.push({ label: part, full: cur });
  }
  return crumbs;
}

export function Breadcrumbs({ mount, path, onNavigate }: BreadcrumbsProps): JSX.Element {
  const crumbs = buildCrumbs(mount, path);
  return (
    <nav aria-label="Breadcrumb" className="fathom-breadcrumbs">
      {crumbs.map((c, i) => {
        const isLast = i === crumbs.length - 1;
        return (
          <span key={c.full} className="fathom-crumb-item">
            {i > 0 ? <span className="fathom-crumb-sep">/</span> : null}
            {isLast ? (
              <span className="fathom-crumb-current" aria-current="page">
                {c.label}
              </span>
            ) : (
              <button type="button" className="fathom-crumb" onClick={() => onNavigate(c.full)}>
                {c.label}
              </button>
            )}
          </span>
        );
      })}
    </nav>
  );
}
