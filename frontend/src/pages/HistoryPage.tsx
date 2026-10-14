import { useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, History, Loader2, Search } from "lucide-react";
import { getStats, listInvestigations } from "../lib/api";
import type { InvestigationList, InvestigationStats, Severity } from "../lib/types";
import { SEVERITY_ORDER, SOURCE_LABELS, formatRelativeTime, severityStyle, titleCase } from "../lib/format";
import { SeverityBadge } from "../components/SeverityBadge";
import { useAuth } from "../lib/auth";

const PAGE = 20;

export function HistoryPage() {
  const [stats, setStats] = useState<InvestigationStats | null>(null);
  const [list, setList] = useState<InvestigationList | null>(null);
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [offset, setOffset] = useState(0);
  const [mine, setMine] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { me } = useAuth();
  const signedIn = me?.kind === "user";

  useEffect(() => {
    getStats().then(setStats).catch((e) => setError(e.message));
  }, []);

  // Debounce the search box
  useEffect(() => {
    const t = setTimeout(() => {
      setQuery(q);
      setOffset(0);
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  useEffect(() => {
    listInvestigations({ limit: PAGE, offset, severity, q: query, mine: mine || undefined })
      .then(setList)
      .catch((e) => setError(e.message));
  }, [offset, severity, query, mine]);

  return (
    <div className="flex flex-col gap-5">
      {error && <div className="rounded-xl border border-fail/30 bg-fail/8 px-4 py-3 text-sm text-fail">{error}</div>}
      {stats && <StatsRow stats={stats} activeSeverity={severity} onSeverity={(s) => { setSeverity(s); setOffset(0); }} />}

      <section className="card">
        <div className="card-header flex-wrap">
          <h2 className="card-title">
            <History className="h-4 w-4 text-accent" />
            Investigation history
            {list && <span className="rounded-full bg-surface-2 px-2 text-[11px] font-medium text-ink-muted">{list.total}</span>}
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            {signedIn && (
              <div className="flex rounded-lg border border-line p-0.5 text-[11px]">
                {[{ v: false, label: "Everyone" }, { v: true, label: "Mine" }].map((o) => (
                  <button key={o.label} type="button" onClick={() => { setMine(o.v); setOffset(0); }}
                    className={`rounded-md px-2.5 py-1 font-medium ${mine === o.v ? "bg-surface-2 text-ink" : "text-ink-faint hover:text-ink-muted"}`}>
                    {o.label}
                  </button>
                ))}
              </div>
            )}
            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value as Severity | ""); setOffset(0); }}
              aria-label="Filter by severity"
              className="rounded-lg border border-line bg-canvas/60 px-2 py-1.5 text-xs text-ink focus:border-accent/60 focus:outline-none"
            >
              <option value="">All severities</option>
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>{severityStyle(s).label}</option>
              ))}
            </select>
            <label className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-faint" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search content, file, ID…"
                aria-label="Search investigations"
                className="w-56 rounded-lg border border-line bg-canvas/60 py-1.5 pl-8 pr-3 text-xs text-ink placeholder:text-ink-faint focus:border-accent/60 focus:outline-none"
              />
            </label>
          </div>
        </div>

        {!list ? (
          <div className="flex items-center gap-2 px-5 py-10 text-sm text-ink-muted"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : list.items.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-ink-muted">
            {query || severity ? "No investigations match these filters." : "No investigations yet — run one from the Investigate tab."}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-[13px]">
                <thead className="text-[11px] uppercase tracking-wider text-ink-faint">
                  <tr className="border-b border-line">
                    <th className="px-5 py-2.5 font-medium">Score</th>
                    <th className="px-3 py-2.5 font-medium">Subject</th>
                    <th className="px-3 py-2.5 font-medium">Classification</th>
                    <th className="px-3 py-2.5 font-medium">Source</th>
                    {signedIn && <th className="px-3 py-2.5 font-medium">Analyst</th>}
                    <th className="px-3 py-2.5 text-right font-medium">IOCs</th>
                    <th className="px-5 py-2.5 text-right font-medium">When</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {list.items.map((item) => (
                    <tr
                      key={item.investigation_id}
                      onClick={() => (window.location.hash = `#/investigations/${item.investigation_id}`)}
                      className="cursor-pointer transition-colors hover:bg-surface-2/50"
                    >
                      <td className="px-5 py-2.5">
                        <div className="flex items-center gap-2">
                          <span className={`w-7 font-mono font-semibold tabular-nums ${severityStyle(item.severity).text}`}>{Math.round(item.score)}</span>
                          <SeverityBadge severity={item.severity} />
                        </div>
                      </td>
                      <td className="max-w-[340px] px-3 py-2.5">
                        <a href={`#/investigations/${item.investigation_id}`} className="block truncate text-ink hover:text-accent" onClick={(e) => e.stopPropagation()}>
                          {item.source_name ?? (item.input_preview.trim().split("\n")[0] || "(empty)")}
                        </a>
                      </td>
                      <td className="px-3 py-2.5 text-ink-muted">{item.classification === "no_threat_identified" ? "—" : titleCase(item.classification)}</td>
                      <td className="px-3 py-2.5 text-ink-muted">{SOURCE_LABELS[item.source_type] ?? item.source_type}</td>
                      {signedIn && <td className="max-w-[160px] truncate px-3 py-2.5 text-ink-faint">{item.owner_email ?? "—"}</td>}
                      <td className="px-3 py-2.5 text-right font-mono tabular-nums text-ink-muted">{item.ioc_count}</td>
                      <td className="whitespace-nowrap px-5 py-2.5 text-right text-ink-faint" title={new Date(item.created_at).toLocaleString()}>
                        {formatRelativeTime(item.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-line px-5 py-2.5 text-xs text-ink-faint">
              <span>
                {offset + 1}–{Math.min(offset + PAGE, list.total)} of {list.total}
              </span>
              <div className="flex gap-1">
                <button type="button" className="btn-ghost px-2 py-1" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
                  <ChevronLeft className="h-3.5 w-3.5" /> Prev
                </button>
                <button type="button" className="btn-ghost px-2 py-1" disabled={offset + PAGE >= list.total} onClick={() => setOffset(offset + PAGE)}>
                  Next <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function StatsRow({ stats, activeSeverity, onSeverity }: {
  stats: InvestigationStats;
  activeSeverity: Severity | "";
  onSeverity: (s: Severity | "") => void;
}) {
  const highRisk = stats.by_severity.CRITICAL + stats.by_severity.HIGH;
  const maxSev = Math.max(1, ...Object.values(stats.by_severity));
  const maxCls = useMemo(() => Math.max(1, ...stats.top_classifications.map((c) => c.count)), [stats]);

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)_minmax(0,1.1fr)]">
      <div className="grid grid-cols-2 gap-3">
        <Tile label="Investigations" value={stats.total} />
        <Tile label="Last 7 days" value={stats.last_7_days} />
        <Tile label="Average score" value={stats.average_score} />
        <Tile label="High or critical" value={stats.total ? `${Math.round((highRisk / stats.total) * 100)}%` : "—"} sub={`${highRisk} investigations`} />
      </div>

      <section className="card p-4">
        <h3 className="text-[12px] font-semibold text-ink">Severity distribution</h3>
        <p className="text-[11px] text-ink-faint">Click a row to filter the table</p>
        <ul className="mt-3 space-y-1">
          {SEVERITY_ORDER.map((sev) => {
            const count = stats.by_severity[sev] ?? 0;
            const s = severityStyle(sev);
            const active = activeSeverity === sev;
            return (
              <li key={sev}>
                <button
                  type="button"
                  onClick={() => onSeverity(active ? "" : sev)}
                  title={`${s.label}: ${count} investigation${count === 1 ? "" : "s"}`}
                  className={`grid w-full grid-cols-[64px_minmax(0,1fr)_36px] items-center gap-3 rounded-md px-2 py-1.5 text-left transition-colors ${active ? "bg-surface-2" : "hover:bg-surface-2/60"}`}
                >
                  <span className="text-[12px] text-ink-muted">{s.label}</span>
                  <span className="h-2 overflow-hidden rounded-full bg-line/60">
                    <span className="block h-full rounded-full" style={{ width: `${count ? Math.max(3, (count / maxSev) * 100) : 0}%`, background: s.stroke }} />
                  </span>
                  <span className="text-right font-mono text-[12px] tabular-nums text-ink">{count}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="card p-4">
        <h3 className="text-[12px] font-semibold text-ink">Top threat classifications</h3>
        <p className="text-[11px] text-ink-faint">Investigations by primary classification</p>
        {stats.top_classifications.length === 0 ? (
          <p className="mt-6 text-[12px] text-ink-muted">No threats classified yet.</p>
        ) : (
          <ul className="mt-3 space-y-2.5">
            {stats.top_classifications.map((c) => (
              <li key={c.classification} title={`${titleCase(c.classification)}: ${c.count}`} className="grid grid-cols-[minmax(0,1fr)_36px] items-center gap-3 px-2">
                <div>
                  <div className="truncate text-[12px] text-ink-muted">{titleCase(c.classification)}</div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-line/60">
                    <div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(3, (c.count / maxCls) * 100)}%` }} />
                  </div>
                </div>
                <span className="text-right font-mono text-[12px] tabular-nums text-ink">{c.count}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function Tile({ label, value, sub }: { label: string; value: number | string; sub?: string }) {
  return (
    <div className="card px-4 py-3">
      <div className="text-[11px] text-ink-faint">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-ink">{value}</div>
      {sub && <div className="text-[11px] text-ink-faint">{sub}</div>}
    </div>
  );
}
