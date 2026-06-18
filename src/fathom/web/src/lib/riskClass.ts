// Path-pattern risk classification (frontend safety aid). Fathom can move/delete files, so the UI
// marks *what kind* of data a path is, to make a careless delete/dedup harder. This is a heuristic
// signal from the path/name only — it never changes what the server allows; it just colours the UI
// and hardens the confirm step. Four classes, by descending danger:
//
//   os       (red)    — operating-system files; deleting these can break the host.
//   services (orange) — application/service state (Docker layers, DB data dirs, container volumes).
//   config   (yellow) — config / compose / env files: small but precious, often unbacked-up.
//   user     (none)   — ordinary user data (media, documents, photos): the safe-to-tidy default.
//
// Precedence: an OS path wins over everything (most dangerous), then services, then a config file,
// then user. A config FILE under an OS path is still treated as OS (deleting /etc/* is dangerous).

export type RiskClass = "os" | "services" | "config" | "user";

export interface RiskMeta {
  cls: RiskClass;
  label: string;
  badge: string; // CSS badge class
  caution: string | null; // shown in confirm dialogs; null for user data
}

export const RISK_META: Record<RiskClass, RiskMeta> = {
  os: {
    cls: "os",
    label: "OS",
    badge: "fathom-badge-risk-os",
    caution: "Operating-system files — deleting these can break the host. Proceed with extreme care.",
  },
  services: {
    cls: "services",
    label: "Service data",
    badge: "fathom-badge-risk-services",
    caution:
      "Application / service data (containers, databases) — deleting or moving it can break running apps.",
  },
  config: {
    cls: "config",
    label: "Config",
    badge: "fathom-badge-risk-config",
    caution: "Config / compose / env file — small but precious, and often not backed up. Keep a copy.",
  },
  user: { cls: "user", label: "", badge: "", caution: null },
};

// Unambiguous OS markers — matched as a whole component ANYWHERE in the path (these names almost
// never occur in user data, so even .../backup/etc/passwd reads as OS).
const STRONG_OS = new Set([
  "etc",
  "boot",
  "sys",
  "proc",
  "windows",
  "system32",
  "winsxs",
  "programdata",
  "program files",
  "program files (x86)",
]);

// Ambiguous OS dirs — OS only when they are the path ROOT (first real component). "lib"/"bin"/"var"
// legitimately appear inside user and service trees (e.g. /var/lib/docker), so matching them
// anywhere over-flags; the services check below also runs first so /var/lib/docker stays services.
const ROOT_OS = new Set([
  "usr",
  "bin",
  "sbin",
  "lib",
  "lib64",
  "dev",
  "run",
  "root",
  "var",
]);

// Service / application-state directories. A component equal to one of these, or containing
// "docker" (docker_data, docker_images, docker-data, docker_only…), marks the subtree as services.
const SERVICE_DIRS = new Set([
  "overlay2",
  "containers",
  "containerd",
  "volumes",
  "pgdata",
  "postgres",
  "postgresql",
  "mysql",
  "mariadb",
  "mongodb",
  "mongo",
  "redis",
  "valkey",
  "etcd",
  "appdata",
  ".config",
]);

// Config / compose / env files, matched on the basename (lowercased).
function isConfigFile(name: string): boolean {
  const n = name.toLowerCase();
  if (n === ".env" || n.endsWith(".env")) return true;
  if (n.startsWith("docker-compose") || n.startsWith("compose.")) return true;
  if (n === "dockerfile" || n.startsWith("dockerfile.")) return true;
  return (
    n.endsWith(".conf") ||
    n.endsWith(".cfg") ||
    n.endsWith(".ini") ||
    n.endsWith(".service") ||
    n.endsWith(".nginx") ||
    n === "nginx.conf"
  );
}

function components(path: string): string[] {
  return path
    .split("/")
    .map((c) => c.trim().toLowerCase())
    .filter(Boolean);
}

/** Classify a path into a risk class from its components + basename (heuristic, UI-only). */
export function classifyPath(path: string, name?: string): RiskClass {
  const comps = components(path);
  const base = (name ?? comps[comps.length - 1] ?? "").toLowerCase();

  // Strip a leading "scan" mount alias so /scan/etc/... still reads as OS (agents mount under /scan).
  const real = comps[0] === "scan" ? comps.slice(1) : comps;

  // Unambiguous OS markers win first (most dangerous) — even /etc/nginx/nginx.conf reads as OS.
  if (real.some((c) => STRONG_OS.has(c))) return "os";

  // A config / compose / env FILE is yellow — checked before the docker heuristic so that
  // "docker-compose.yml" (which contains "docker") is config, not falsely flagged as service data.
  if (isConfigFile(base)) return "config";

  // Service/app state: a known service dir, or any component mentioning docker (docker_data,
  // docker_images…). Runs before the ROOT_OS check so /var/lib/docker is services, not OS.
  if (real.some((c) => SERVICE_DIRS.has(c) || c.includes("docker"))) return "services";

  // Ambiguous OS dirs only count when they are the path root (e.g. an actual /usr or /var scan).
  if (real.length > 0 && ROOT_OS.has(real[0])) return "os";

  return "user";
}

/** Convenience: the display metadata for a path (or null for plain user data → no badge). */
export function riskFor(path: string, name?: string): RiskMeta | null {
  const meta = RISK_META[classifyPath(path, name)];
  return meta.cls === "user" ? null : meta;
}

/** Summarise a set of paths: the non-user classes present + whether any are high-risk (OS/service). */
export function riskSummary(paths: string[]): { classes: RiskClass[]; highRisk: boolean } {
  const seen = new Set<RiskClass>();
  for (const p of paths) {
    const c = classifyPath(p);
    if (c !== "user") seen.add(c);
  }
  const classes = [...seen];
  return { classes, highRisk: seen.has("os") || seen.has("services") };
}
