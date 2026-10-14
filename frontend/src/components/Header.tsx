import { History, Radar, Server, ShieldCheck } from "lucide-react";
import type { HealthResponse } from "../lib/types";
import type { Route } from "../lib/useHashRoute";

export type ApiState = { kind: "checking" } | { kind: "online"; health: HealthResponse } | { kind: "offline" };

const NAV = [
  { href: "#/", label: "Investigate", icon: Radar, pages: ["investigate"] },
  { href: "#/history", label: "History", icon: History, pages: ["history", "investigation"] },
  { href: "#/system", label: "System", icon: Server, pages: ["system"] },
];

export function Header({ api, route }: { api: ApiState; route: Route }) {
  const dot = api.kind === "online" ? "bg-ok" : api.kind === "offline" ? "bg-fail" : "bg-sev-medium animate-pulse";
  const label =
    api.kind === "online" ? `API v${api.health.version}` : api.kind === "offline" ? "API offline" : "Connecting…";

  return (
    <header className="sticky top-0 z-20 border-b border-line bg-canvas/85 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-[1500px] items-center gap-4 px-4 sm:px-6">
        <a href="#/" className="flex items-center gap-3">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent/15 ring-1 ring-accent/30">
            <ShieldCheck className="h-4.5 w-4.5 text-accent" />
          </div>
          <div className="hidden leading-tight sm:block">
            <div className="text-[15px] font-semibold tracking-tight">
              Recon<span className="text-accent">IQ</span>
            </div>
            <div className="text-[11px] text-ink-faint">Evidence. Intelligence. Trust.</div>
          </div>
        </a>

        <nav className="ml-2 flex items-center gap-1" aria-label="Main">
          {NAV.map(({ href, label: text, icon: Icon, pages }) => {
            const active = pages.includes(route.page);
            return (
              <a
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[13px] font-medium transition-colors ${
                  active ? "bg-surface-2 text-ink" : "text-ink-muted hover:text-ink"
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden sm:inline">{text}</span>
              </a>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 text-xs text-ink-muted" title={api.kind === "online" ? api.health.environment : undefined}>
          <span className={`h-2 w-2 rounded-full ${dot}`} />
          <span className="hidden truncate sm:inline">{label}</span>
        </div>
      </div>
    </header>
  );
}
