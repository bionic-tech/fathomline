// Byte / SI / date formatting for the viewer (frontend ADD §8/§9). Sizes are shown both as
// human-readable units and verbatim in the chart data-table alternatives, so the numbers are
// reachable without reading the chart (WCAG 2.1 AA, frontend ADD §9).

// Familiar units (KB/MB/GB/TB/PB) rather than the technically-precise IEC binary names
// (KiB/MiB/…) — most people read "GB"/"TB", and "MiB" looks like a typo to a non-engineer. The
// scale stays base-1024 (1 KB = 1024 B), matching how filesystems / `du` / `df` / ZFS actually
// account usage (Windows Explorer uses this same KB-label + 1024-scale convention). The exact
// integer byte count is always one hover away via `formatBytesExact`, so no precision is lost.
const UNITS = ["B", "KB", "MB", "GB", "TB", "PB", "EB"] as const;
const SCALE = 1024;

/** Format a byte count as a human-readable size (e.g. 1536 → "1.50 KB", 1024**4 → "1.00 TB"). */
export function formatBytes(bytes: number, fractionDigits = 2): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < SCALE) return `${bytes} B`;
  let value = bytes;
  let unit = 0;
  while (value >= SCALE && unit < UNITS.length - 1) {
    value /= SCALE;
    unit += 1;
  }
  return `${value.toFixed(fractionDigits)} ${UNITS[unit]}`;
}

/** Exact integer byte count with thousands separators (for the a11y data table). */
export function formatBytesExact(bytes: number): string {
  return `${Math.trunc(bytes).toLocaleString()} B`;
}

/** Format an ISO timestamp as a short, locale-aware date-time. */
export function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Format a POSIX mtime (seconds since the epoch, as a float) as a human date-time. */
export function formatUnixTime(seconds: number): string {
  if (!seconds || Number.isNaN(seconds)) return "—";
  const d = new Date(seconds * 1000);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Display form of a catalogue path: drop the agent's ``/scan`` mount prefix so the path reads as
 * the volume-relative location (e.g. ``/scan/tank/n8n`` → ``/tank/n8n``). The host
 * + volume are shown alongside; the raw path is kept verbatim in the catalogue/API. */
export function displayPath(path: string): string {
  if (path === "/scan") return "/";
  const stripped = path.replace(/^\/scan(?=\/)/, "");
  return stripped || path;
}

/** The leaf name of a materialised path (display label fallback). */
export function basename(path: string): string {
  const trimmed = path.replace(/\/+$/, "");
  const idx = trimmed.lastIndexOf("/");
  return idx === -1 ? trimmed : trimmed.slice(idx + 1) || trimmed;
}
