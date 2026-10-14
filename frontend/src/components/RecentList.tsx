import { useEffect, useState } from "react";
import { ArrowRight, History } from "lucide-react";
import { listInvestigations } from "../lib/api";
import type { InvestigationSummary } from "../lib/types";
import { SOURCE_LABELS, formatRelativeTime, severityStyle } from "../lib/format";

export function RecentList({ refreshKey, activeId }: { refreshKey: number; activeId?: string }) {
  const [items, setItems] = useState<InvestigationSummary[] | null>(null);

  useEffect(() => {
    listInvestigations({ limit: 6 })
      .then((r) => setItems(r.items))
      .catch(() => setItems(null));
  }, [refreshKey]);

  if (items === null) return null;

  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <History className="h-4 w-4 text-accent" />
          Recent investigations
        </h2>
        <a href="#/history" className="btn-ghost px-2 py-1 text-xs">
          All <ArrowRight className="h-3.5 w-3.5" />
        </a>
      </div>
      {items.length === 0 ? (
        <p className="px-5 py-4 text-xs text-ink-faint">Your investigations will appear here.</p>
      ) : (
        <ul className="divide-y divide-line">
          {items.map((e) => <RecentRow key={e.investigation_id} item={e} active={e.investigation_id === activeId} />)}
        </ul>
      )}
    </section>
  );
}

export function RecentRow({ item, active }: { item: InvestigationSummary; active?: boolean }) {
  const s = severityStyle(item.severity);
  return (
    <li>
      <a
        href={`#/investigations/${item.investigation_id}`}
        className={`flex items-center gap-3 px-4 py-2.5 transition-colors ${active ? "bg-accent/8" : "hover:bg-surface-2/60"}`}
      >
        <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-md font-mono text-xs font-bold ring-1 ring-inset ${s.text} ${s.bg} ${s.ring}`}>
          {Math.round(item.score)}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[12.5px] text-ink">
            {item.source_name ?? (item.input_preview.trim().split("\n")[0] || "(empty)")}
          </span>
          <span className="block text-[11px] text-ink-faint">
            {SOURCE_LABELS[item.source_type] ?? item.source_type} · {s.label} · {formatRelativeTime(item.created_at)}
          </span>
        </span>
      </a>
    </li>
  );
}
