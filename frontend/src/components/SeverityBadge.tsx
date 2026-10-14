import { severityStyle } from "../lib/format";

export function SeverityBadge({ severity, size = "sm" }: { severity?: string | null; size?: "sm" | "lg" }) {
  const s = severityStyle(severity);
  const sizing = size === "lg" ? "px-2.5 py-1 text-xs" : "px-1.5 py-0.5 text-[11px]";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md font-semibold uppercase tracking-wider ring-1 ring-inset ${sizing} ${s.text} ${s.bg} ${s.ring}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {s.label}
    </span>
  );
}
