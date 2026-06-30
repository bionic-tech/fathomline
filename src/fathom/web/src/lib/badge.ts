// Semantic badge mapping: a status/result string → one semantic badge class so colour always
// means the same thing across the app (success=green, info=blue, warning=amber, danger=red,
// neutral=grey). Reserve red for genuine failures only — a normal resting state (idle) is neutral,
// an in-flight/pending state is amber, a plain fact (set/built) is blue. Unknown → neutral.

const SUCCESS = new Set([
  "ok",
  "served",
  "granted",
  "success",
  "succeeded",
  "completed",
  "complete",
  "applied",
  "done",
  "active",
  "online",
  "keeper",
  "healthy",
  "passed",
]);
const INFO = new Set([
  "set",
  "built",
  "created",
  "registered",
  "enrolled",
  "initiated",
  "reported",
  "updated",
  "metadata",
  "skipped",
]);
const WARNING = new Set([
  "dispatched",
  "pending",
  "queued",
  "scheduled",
  "deferred",
  "partial",
  "retrying",
  "fullbit",
  "warning",
]);
const DANGER = new Set([
  "failed",
  "fail",
  "error",
  "denied",
  "revoked",
  "rejected",
  "offline",
  "broken",
  "expired",
  "aborted",
  "critical",
]);

/** Map a status/result token to its semantic badge class (idle / unknown → neutral). */
export function semanticBadgeClass(value: string | null | undefined): string {
  const v = (value ?? "").toLowerCase().trim();
  if (SUCCESS.has(v)) return "fathom-badge-success";
  if (INFO.has(v)) return "fathom-badge-info";
  if (WARNING.has(v)) return "fathom-badge-warning";
  if (DANGER.has(v)) return "fathom-badge-danger";
  return "fathom-badge-neutral";
}
