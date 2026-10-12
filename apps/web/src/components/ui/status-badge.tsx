import { STATUS_LABELS, statusClass } from "@/lib/scans";
import { cn } from "@/lib/utils";

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  if (!status) return null;
  return (
    <span className={cn("rounded px-2 py-0.5 text-xs font-medium", statusClass(status), className)}>
      {STATUS_LABELS[status] || status}
    </span>
  );
}

export function ErrorNote({ message }: { message?: string | null }) {
  if (!message) return null;
  return (
    <p role="alert" className="mt-2 rounded bg-red-50 p-2 text-sm text-red-700">
      {message}
    </p>
  );
}
