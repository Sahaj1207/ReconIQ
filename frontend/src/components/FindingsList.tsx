import { AlertTriangle, ShieldCheck } from "lucide-react";
import type { RiskFinding } from "../lib/types";
import { SEVERITY_ORDER, severityStyle } from "../lib/format";
import { SeverityBadge } from "./SeverityBadge";

export function FindingsList({ findings }: { findings: RiskFinding[] }) {
  const sorted = [...findings].sort((a, b) => {
    const sa = SEVERITY_ORDER.indexOf((a.severity ?? "INFORMATIONAL").toUpperCase() as never);
    const sb = SEVERITY_ORDER.indexOf((b.severity ?? "INFORMATIONAL").toUpperCase() as never);
    return b.score_impact - a.score_impact || sa - sb;
  });

  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <AlertTriangle className="h-4 w-4 text-accent" />
          Findings
          <span className="rounded-full bg-surface-2 px-2 text-[11px] font-medium text-ink-muted">{findings.length}</span>
        </h2>
      </div>

      {sorted.length === 0 ? (
        <div className="flex items-center gap-3 px-5 py-6 text-sm text-ink-muted">
          <ShieldCheck className="h-5 w-5 text-ok" />
          No rules produced findings for this evidence.
        </div>
      ) : (
        <ul className="divide-y divide-line">
          {sorted.map((f) => {
            const s = severityStyle(f.severity);
            return (
              <li key={f.finding_id} className="flex gap-4 px-5 py-3.5">
                <div className="mt-1 h-8 w-1 shrink-0 rounded-full" style={{ background: s.stroke }} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">{f.title}</span>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <p className="mt-0.5 text-[13px] text-ink-muted">{f.description}</p>
                  <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-ink-faint">
                    <span>{f.rule_id ?? f.finding_id.replace(/_FINDING$/, "")}</span>
                    {f.mitre_techniques?.map((t) => (
                      <a key={t.id} href={t.url} target="_blank" rel="noreferrer" title={t.name} className="text-accent/80 hover:text-accent">
                        {t.id}
                      </a>
                    ))}
                  </div>
                </div>
                <div className="shrink-0 text-right">
                  <div className={`font-mono text-sm font-semibold tabular-nums ${f.score_impact > 0 ? s.text : "text-ink-faint"}`}>
                    +{f.score_impact}
                  </div>
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">points</div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
