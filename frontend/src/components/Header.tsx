import { useEffect, useRef, useState } from "react";
import { ChevronDown, History, LogOut, Radar, Server, ShieldCheck, UserCog } from "lucide-react";
import { useAuth } from "../lib/auth";
import type { HealthResponse } from "../lib/types";
import type { Route } from "../lib/useHashRoute";

export type ApiState = { kind: "checking" } | { kind: "online"; health: HealthResponse } | { kind: "offline" };

export function Header({ api, route }: { api: ApiState; route: Route }) {
  const { me, can } = useAuth();
  const nav = [
    { href: "#/", label: "Investigate", icon: Radar, pages: ["investigate"], show: true },
    { href: "#/history", label: "History", icon: History, pages: ["history", "investigation"], show: true },
    { href: "#/admin", label: "Admin", icon: UserCog, pages: ["admin"], show: can("admin") && me?.kind === "user" },
    { href: "#/system", label: "System", icon: Server, pages: ["system"], show: true },
  ];
  const dot = api.kind === "online" ? "bg-ok" : api.kind === "offline" ? "bg-fail" : "bg-sev-medium animate-pulse";

  return (
    <header className="sticky top-0 z-20 border-b border-line bg-canvas/85 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-[1500px] items-center gap-3 px-4 sm:px-6">
        <a href="#/" className="flex items-center gap-3">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent/15 ring-1 ring-accent/30">
            <ShieldCheck className="h-4.5 w-4.5 text-accent" />
          </div>
          <div className="hidden leading-tight md:block">
            <div className="text-[15px] font-semibold tracking-tight">
              Recon<span className="text-accent">IQ</span>
            </div>
            <div className="text-[11px] text-ink-faint">Evidence. Intelligence. Trust.</div>
          </div>
        </a>

        <nav className="ml-1 flex items-center gap-1" aria-label="Main">
          {nav.filter((n) => n.show).map(({ href, label, icon: Icon, pages }) => {
            const active = pages.includes(route.page);
            return (
              <a
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                title={label}
                className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[13px] font-medium transition-colors ${
                  active ? "bg-surface-2 text-ink" : "text-ink-muted hover:text-ink"
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden sm:inline">{label}</span>
              </a>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-2">
          <span
            className="hidden items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 text-xs text-ink-muted lg:flex"
            title={api.kind === "online" ? `API v${api.health.version} · ${api.health.environment}` : undefined}
          >
            <span className={`h-2 w-2 rounded-full ${dot}`} />
            {api.kind === "online" ? "Online" : api.kind === "offline" ? "API offline" : "Connecting…"}
          </span>
          {me?.kind === "user" && me.user && <UserMenu name={me.user.name || me.user.email} email={me.user.email} role={me.role} />}
        </div>
      </div>
    </header>
  );
}

function UserMenu({ name, email, role }: { name: string; email: string; role: string }) {
  const { signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex items-center gap-2 rounded-full border border-line bg-surface py-1 pl-1 pr-2 text-xs text-ink hover:border-line-strong"
      >
        <span className="grid h-6 w-6 place-items-center rounded-full bg-accent/20 text-[11px] font-semibold uppercase text-accent">
          {name.slice(0, 1)}
        </span>
        <span className="hidden max-w-[140px] truncate sm:inline">{name}</span>
        <ChevronDown className="h-3 w-3 text-ink-faint" />
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-1 w-60 overflow-hidden rounded-lg border border-line-strong bg-surface shadow-xl shadow-black/40">
          <div className="border-b border-line px-3 py-2.5">
            <div className="truncate text-[13px] text-ink">{email}</div>
            <div className="text-[11px] capitalize text-ink-faint">{role}</div>
          </div>
          <a href="#/system" onClick={() => setOpen(false)} className="block px-3 py-2 text-[13px] text-ink-muted hover:bg-surface-2 hover:text-ink">
            Account &amp; system
          </a>
          <button type="button" onClick={signOut} className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-ink-muted hover:bg-surface-2 hover:text-ink">
            <LogOut className="h-3.5 w-3.5" /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}
