import { ExternalLink, Target } from "lucide-react";
import type { RiskAssessment } from "../lib/types";
import { titleCase } from "../lib/format";

const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Defense Evasion",
  "Credential Access", "Command and Control",
];

export function AttackPanel({ risk }: { risk: RiskAssessment }) {
  const techniques = risk.mitre_techniques ?? [];
  const rank = (tactic: string) => {
    const i = TACTIC_ORDER.indexOf(tactic);
    return i < 0 ? TACTIC_ORDER.length : i;
  };
  const tactics = [...new Set(techniques.map((t) => t.tactic))].sort((a, b) => rank(a) - rank(b));
  const categories = risk.threat_categories ?? [];
  const noThreat = risk.classification === "no_threat_identified";

  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Target className="h-4 w-4 text-accent" />
          Threat classification
        </h2>
      </div>
      <div className="p-5">
        <div className="text-[11px] uppercase tracking-wider text-ink-faint">Primary classification</div>
        <div className={`mt-1 text-lg font-semibold ${noThreat ? "text-ink-muted" : "text-ink"}`}>
          {titleCase(risk.classification ?? "unknown")}
        </div>
        {categories.length > 1 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {categories.slice(1).map((c) => (
              <span key={c} className="chip bg-surface-2 text-ink-muted">
                {titleCase(c)}
              </span>
            ))}
          </div>
        )}

        <div className="mt-5 text-[11px] uppercase tracking-wider text-ink-faint">MITRE ATT&CK</div>
        {techniques.length === 0 ? (
          <p className="mt-1 text-[13px] text-ink-muted">No techniques mapped.</p>
        ) : (
          <div className="mt-2 space-y-3">
            {tactics.map((tactic) => (
              <div key={tactic}>
                <div className="text-[12px] font-medium text-ink-muted">{tactic}</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {techniques
                    .filter((t) => t.tactic === tactic)
                    .map((t) => (
                      <a
                        key={t.id}
                        href={t.url}
                        target="_blank"
                        rel="noreferrer"
                        className="group inline-flex items-center gap-1.5 rounded-md border border-line bg-canvas/50 px-2 py-1 text-[12px] text-ink transition-colors hover:border-accent/50"
                      >
                        <span className="font-mono text-[11px] text-accent">{t.id}</span>
                        {t.name.replace(/^.*?: /, "")}
                        <ExternalLink className="h-3 w-3 text-ink-faint group-hover:text-accent" />
                      </a>
                    ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
