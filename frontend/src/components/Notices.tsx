import { AlertOctagon, Info } from "lucide-react";
import type { InvestigationResult } from "../lib/types";

/** Pipeline errors/warnings plus a hint when no threat-intel provider is configured. */
export function Notices({ result, intelConfigured }: { result: InvestigationResult; intelConfigured?: boolean }) {
  const showIntelHint = intelConfigured === false;
  if (!result.errors.length && !result.warnings.length && !showIntelHint) return null;

  return (
    <div className="flex flex-col gap-2">
      {result.errors.map((e) => (
        <Notice key={e} tone="error" text={e} />
      ))}
      {result.warnings.map((w) => (
        <Notice key={w} tone="warn" text={w} />
      ))}
      {showIntelHint && (
        <Notice
          tone="info"
          text="No threat-intelligence provider is enabled, so indicators were scored on their own characteristics only. Add a provider key (e.g. VIRUSTOTAL_API_KEY) in backend/.env — see System for the full list."
        />
      )}
    </div>
  );
}

function Notice({ tone, text }: { tone: "error" | "warn" | "info"; text: string }) {
  const styles = {
    error: "border-fail/30 bg-fail/8 text-fail",
    warn: "border-sev-medium/30 bg-sev-medium/8 text-sev-medium",
    info: "border-line bg-surface-2/60 text-ink-muted",
  }[tone];
  const Icon = tone === "info" ? Info : AlertOctagon;
  return (
    <div className={`flex items-start gap-2.5 rounded-lg border px-4 py-2.5 text-[13px] ${styles}`} role={tone === "error" ? "alert" : "status"}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{text}</span>
    </div>
  );
}
