import { Bot, FileText, Info } from "lucide-react";
import type { AnalystReport } from "../lib/types";

export function AnalystCard({ report }: { report: AnalystReport }) {
  const byModel = report.generated_by !== "template";
  const provider = report.generated_by === "gemini" ? "Gemini" : "Claude";
  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          {byModel ? <Bot className="h-4 w-4 text-accent" /> : <FileText className="h-4 w-4 text-accent" />}
          Analyst summary
        </h2>
        <span className="chip bg-surface-2 text-ink-muted" title={report.model ?? undefined}>
          {byModel ? `Written by ${report.model ?? provider}` : "Deterministic template"}
        </span>
      </div>
      <div className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div>
          <p className="text-[14px] leading-relaxed text-ink">{report.summary}</p>
          {report.key_findings.length > 0 && (
            <>
              <h3 className="mt-4 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">Key findings</h3>
              <ul className="mt-1.5 space-y-1.5">
                {report.key_findings.map((k) => (
                  <li key={k} className="flex gap-2 text-[13px] text-ink-muted">
                    <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-accent" />
                    {k}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
        <div className="rounded-lg border border-line bg-canvas/50 p-4">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-ink-faint">Recommended actions</h3>
          <ol className="mt-2 space-y-2">
            {report.recommended_actions.map((a, i) => (
              <li key={a} className="flex gap-2.5 text-[13px] text-ink">
                <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-accent/15 font-mono text-[10px] font-semibold text-accent">
                  {i + 1}
                </span>
                {a}
              </li>
            ))}
          </ol>
        </div>
      </div>
      <div className="flex items-start gap-2 border-t border-line px-5 py-2.5 text-[11px] text-ink-faint">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          {report.note ? `${report.note} ` : ""}
          {report.disclaimer}
        </span>
      </div>
    </section>
  );
}
