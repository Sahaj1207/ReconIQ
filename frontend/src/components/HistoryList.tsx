import { History, X } from "lucide-react";
import type { InvestigationResult } from "../lib/types";
import { formatRelativeTime, severityStyle } from "../lib/format";

export interface HistoryEntry {
  id: string;
  text: string;
  result: InvestigationResult;
}

interface Props {
  entries: HistoryEntry[];
  activeId?: string;
  onSelect: (entry: HistoryEntry) => void;
  onClear: () => void;
}

export function HistoryList({ entries, activeId, onSelect, onClear }: Props) {
  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <History className="h-4 w-4 text-accent" />
          Recent investigations
        </h2>
        {entries.length > 0 && (
          <button type="button" onClick={onClear} className="btn-ghost px-2 py-1 text-xs">
            <X className="h-3.5 w-3.5" /> Clear
          </button>
        )}
      </div>
      {entries.length === 0 ? (
        <p className="px-5 py-4 text-xs text-ink-faint">Investigations you run are kept in this browser.</p>
      ) : (
        <ul className="max-h-72 divide-y divide-line overflow-y-auto">
          {entries.map((e) => {
            const risk = e.result.risk_summary;
            const s = severityStyle(risk?.severity);
            const active = e.id === activeId;
            return (
              <li key={e.id}>
                <button
                  type="button"
                  onClick={() => onSelect(e)}
                  className={`flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors ${active ? "bg-accent/8" : "hover:bg-surface-2/60"}`}
                >
                  <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-md font-mono text-xs font-bold ring-1 ring-inset ${s.text} ${s.bg} ${s.ring}`}>
                    {Math.round(risk?.total_score ?? 0)}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[12.5px] text-ink">{e.text.trim().split("\n")[0] || "(empty)"}</span>
                    <span className="block text-[11px] text-ink-faint">
                      {s.label} · {formatRelativeTime(e.result.timestamp)}
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
