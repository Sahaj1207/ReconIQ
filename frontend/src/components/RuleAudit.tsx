import { useState } from "react";
import { ChevronDown, ListChecks } from "lucide-react";
import type { AppliedRule } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";

export function RuleAudit({ rules }: { rules: AppliedRule[] }) {
  const [showAll, setShowAll] = useState(false);
  const matched = rules.filter((r) => r.matched);
  const visible = showAll ? rules : matched;

  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <ListChecks className="h-4 w-4 text-accent" />
          Rule audit trail
        </h2>
        <div className="flex rounded-lg border border-line p-0.5 text-[11px]">
          {[
            { v: false, label: `Matched (${matched.length})` },
            { v: true, label: `All (${rules.length})` },
          ].map((o) => (
            <button
              key={o.label}
              type="button"
              onClick={() => setShowAll(o.v)}
              className={`rounded-md px-2 py-0.5 font-medium ${showAll === o.v ? "bg-surface-2 text-ink" : "text-ink-faint hover:text-ink-muted"}`}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="px-5 py-6 text-sm text-ink-muted">No rules matched.</div>
      ) : (
        <ul className="divide-y divide-line">
          {visible.map((r) => (
            <RuleRow key={r.rule_id} rule={r} />
          ))}
        </ul>
      )}
    </section>
  );
}

function RuleRow({ rule }: { rule: AppliedRule }) {
  const [open, setOpen] = useState(false);
  const hasContext = Object.keys(rule.evidence_context ?? {}).length > 0;

  return (
    <li>
      <button
        type="button"
        onClick={() => hasContext && setOpen((o) => !o)}
        className={`flex w-full items-center gap-3 px-5 py-2.5 text-left ${hasContext ? "hover:bg-surface-2/50" : "cursor-default"}`}
        aria-expanded={hasContext ? open : undefined}
      >
        <span className={`h-2 w-2 shrink-0 rounded-full ${rule.matched ? "bg-accent" : "bg-line-strong"}`} />
        <span className="w-24 shrink-0 font-mono text-[11px] text-ink-faint">{rule.rule_id}</span>
        <span className={`min-w-0 flex-1 truncate text-[13px] ${rule.matched ? "text-ink" : "text-ink-muted"}`} title={rule.description}>
          {rule.rule_name}
        </span>
        <span className="hidden sm:block">
          <SeverityBadge severity={rule.severity} />
        </span>
        <span className="w-12 shrink-0 text-right font-mono text-[12px] tabular-nums text-ink-muted">
          {rule.matched ? `+${rule.weight}` : rule.weight}
        </span>
        <ChevronDown className={`h-3.5 w-3.5 shrink-0 text-ink-faint transition-transform ${open ? "rotate-180" : ""} ${hasContext ? "" : "invisible"}`} />
      </button>
      {open && (
        <div className="px-5 pb-3">
          <p className="mb-2 text-[12px] text-ink-muted">{rule.description}</p>
          <pre className="max-h-56 overflow-auto rounded-lg border border-line bg-canvas/70 p-3 font-mono text-[11px] leading-relaxed text-ink-muted">
            {JSON.stringify(rule.evidence_context, null, 2)}
          </pre>
        </div>
      )}
    </li>
  );
}
