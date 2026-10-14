import { ShieldCheck } from "lucide-react";
import type { HealthResponse } from "../lib/types";

export type ApiState = { kind: "checking" } | { kind: "online"; health: HealthResponse } | { kind: "offline" };

export function Header({ api }: { api: ApiState }) {
  const dot =
    api.kind === "online" ? "bg-ok" : api.kind === "offline" ? "bg-fail" : "bg-sev-medium animate-pulse";
  const label =
    api.kind === "online"
      ? `API online · v${api.health.version} · ${api.health.environment}`
      : api.kind === "offline"
        ? "API offline"
        : "Connecting…";

  return (
    <header className="sticky top-0 z-20 border-b border-line bg-canvas/85 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-[1500px] items-center justify-between gap-4 px-4 sm:px-6">
        <div className="flex items-center gap-3">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent/15 ring-1 ring-accent/30">
            <ShieldCheck className="h-4.5 w-4.5 text-accent" />
          </div>
          <div className="leading-tight">
            <div className="text-[15px] font-semibold tracking-tight">
              Recon<span className="text-accent">IQ</span>
            </div>
            <div className="hidden text-[11px] text-ink-faint sm:block">Evidence. Intelligence. Trust.</div>
          </div>
        </div>

        <div className="flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 text-xs text-ink-muted">
          <span className={`h-2 w-2 rounded-full ${dot}`} />
          <span className="truncate">{label}</span>
        </div>
      </div>
    </header>
  );
}
