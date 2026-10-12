export const TERMINAL_STATUSES = ["completed", "failed", "cancelled", "timed_out"] as const;
export const ACTIVE_STATUSES = ["queued", "running"] as const;

export function isTerminal(status?: string | null): boolean {
  return !!status && (TERMINAL_STATUSES as readonly string[]).includes(status);
}

export function hasReport(status?: string | null): boolean {
  return status === "completed" || status === "timed_out";
}

export const STATUS_LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
  timed_out: "Timed out",
  unverified: "Unverified",
  pending: "Pending verification",
  verified: "Verified",
};

const STATUS_CLASSES: Record<string, string> = {
  queued: "bg-slate-100 text-slate-700",
  running: "bg-blue-100 text-blue-800",
  completed: "bg-green-100 text-green-800",
  failed: "bg-red-100 text-red-800",
  cancelled: "bg-slate-200 text-slate-700",
  timed_out: "bg-amber-100 text-amber-800",
  unverified: "bg-slate-100 text-slate-700",
  pending: "bg-amber-100 text-amber-800",
  verified: "bg-green-100 text-green-800",
  high: "bg-red-100 text-red-800",
  medium: "bg-amber-100 text-amber-800",
  low: "bg-blue-100 text-blue-800",
  info: "bg-slate-100 text-slate-700",
};

export function statusClass(status?: string | null): string {
  return STATUS_CLASSES[status || ""] || "bg-slate-100 text-slate-700";
}

export const CHECK_RESULT_MESSAGES: Record<string, string> = {
  verified: "Ownership verified.",
  record_not_found:
    "No TXT record was found yet. DNS changes can take several minutes to propagate.",
  token_mismatch:
    "A TXT record exists but does not contain the current token. If you rotated the token, update the record.",
  dns_timeout: "The DNS lookup timed out. Try again shortly.",
  dns_error: "The DNS lookup failed. Try again shortly.",
  challenge_expired: "The challenge expired. Generate a new token.",
};
