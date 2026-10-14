import { Clock, FileInput, Gauge, Layers } from "lucide-react";
import type { InvestigationResult } from "../lib/types";
import { SOURCE_LABELS, formatMs, formatPercent, severityStyle, titleCase } from "../lib/format";
import { ExportMenu } from "./ExportMenu";
import { SeverityBadge } from "./SeverityBadge";
import { CopyButton } from "./CopyButton";

function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const arc = 0.75; // 270° gauge
  const dash = c * arc * (Math.min(100, Math.max(0, score)) / 100);
  return (
    <svg viewBox="0 0 128 128" className="h-36 w-36 -rotate-[225deg]" role="img" aria-label={`Risk score ${score} of 100`}>
      <circle cx="64" cy="64" r={r} fill="none" stroke="var(--color-line)" strokeWidth="10" strokeLinecap="round" strokeDasharray={`${c * arc} ${c}`} />
      <circle
        cx="64"
        cy="64"
        r={r}
        fill="none"
        stroke={color}
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={`${dash} ${c}`}
        style={{ transition: "stroke-dasharray 700ms ease-out", filter: `drop-shadow(0 0 6px ${color})` }}
      />
    </svg>
  );
}

const STATUS_TEXT: Record<InvestigationResult["status"], { label: string; cls: string }> = {
  success: { label: "All stages completed", cls: "text-ok" },
  partial_success: { label: "Partial — some stages failed", cls: "text-sev-medium" },
  failed: { label: "Pipeline failed", cls: "text-fail" },
};

export function VerdictCard({ result }: { result: InvestigationResult }) {
  const risk = result.risk_assessment;
  const score = risk?.total_score ?? 0;
  const sev = severityStyle(risk?.severity);
  const totalIocs = Object.values(result.evidence_summary ?? {}).reduce((a, b) => a + b, 0);
  const triggered = risk?.applied_rules.filter((r) => r.matched).length ?? 0;
  const status = STATUS_TEXT[result.status];

  const classification = risk?.classification ?? "no_threat_identified";

  return (
    <section className="card overflow-hidden">
      <div className="flex flex-col gap-6 p-5 md:flex-row md:items-center">
        <div className="relative mx-auto grid shrink-0 place-items-center md:mx-0">
          <ScoreRing score={score} color={sev.stroke} />
          <div className="absolute inset-0 grid place-items-center">
            <div className="text-center">
              <div className={`text-4xl font-bold tabular-nums ${sev.text}`}>{Math.round(score)}</div>
              <div className="text-[10px] uppercase tracking-widest text-ink-faint">Risk / 100</div>
            </div>
          </div>
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-3">
            <SeverityBadge severity={risk?.severity} size="lg" />
            <span className={`text-xs ${status.cls}`}>{status.label}</span>
          </div>
          <h2 className="mt-2 text-xl font-semibold tracking-tight">
            {!risk
              ? "No risk assessment produced"
              : classification === "no_threat_identified"
                ? "No specific threat identified"
                : titleCase(classification)}
          </h2>
          <p className="mt-1 text-sm text-ink-muted">
            {triggered} of {risk?.applied_rules.length ?? 0} deterministic rules matched across {totalIocs} extracted
            indicator{totalIocs === 1 ? "" : "s"}.
          </p>

          <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat icon={<Gauge className="h-3.5 w-3.5" />} label="Confidence" value={formatPercent(risk?.confidence ?? 0)} />
            <Stat icon={<Layers className="h-3.5 w-3.5" />} label="Indicators" value={String(totalIocs)} />
            <Stat icon={<Clock className="h-3.5 w-3.5" />} label="Duration" value={formatMs(result.duration_ms)} />
            <Stat
              icon={<FileInput className="h-3.5 w-3.5" />}
              label="Source"
              value={SOURCE_LABELS[result.source_type] ?? result.source_type}
              title={result.source_name ?? undefined}
            />
          </dl>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line bg-surface-2/40 px-5 py-2.5">
        <div className="flex min-w-0 items-center gap-1 font-mono text-[11px] text-ink-faint">
          <span className="truncate">ID {result.investigation_id}</span>
          <CopyButton value={result.investigation_id} label="Copy investigation ID" />
        </div>
        <ExportMenu investigationId={result.investigation_id} />
      </div>
    </section>
  );
}

function Stat({ icon, label, value, title }: { icon: React.ReactNode; label: string; value: string; title?: string }) {
  return (
    <div className="rounded-lg border border-line bg-canvas/50 px-3 py-2" title={title}>
      <dt className="flex items-center gap-1.5 text-[11px] text-ink-faint">
        {icon}
        {label}
      </dt>
      <dd className="mt-0.5 truncate text-sm font-semibold tabular-nums">{value}</dd>
    </div>
  );
}
