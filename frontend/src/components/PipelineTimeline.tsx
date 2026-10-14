import { CheckCircle2, CircleDashed, Loader2, Workflow, XCircle } from "lucide-react";
import type { StageMetric } from "../lib/types";
import { STAGE_LABELS, formatMs } from "../lib/format";

const DEFAULT_STAGES = ["evidence_collection", "normalization", "validation", "threat_intelligence", "risk_assessment", "summary"];

const FINISHED = new Set(["COMPLETED", "FAILED", "SKIPPED"]);

/**
 * Stage-by-stage view of a pipeline run. With `loading`, stages without a finished metric are shown
 * as pending, and a RUNNING stage (from a live background job) is highlighted.
 */
export function PipelineTimeline({
  metrics,
  loading,
  progress,
}: {
  metrics?: StageMetric[];
  loading?: boolean;
  progress?: number;
}) {
  const finished = metrics?.filter((m) => FINISHED.has(m.status)) ?? [];
  const byName = new Map(finished.map((m) => [m.stage_name, m]));
  const running = metrics?.find((m) => m.status === "RUNNING")?.stage_name;
  const stages = metrics?.length ? metrics.map((m) => m.stage_name) : DEFAULT_STAGES;
  const maxMs = Math.max(0.001, ...finished.map((m) => m.duration_ms));

  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Workflow className="h-4 w-4 text-accent" />
          Pipeline execution
        </h2>
        {loading && progress !== undefined && (
          <span className="font-mono text-[11px] text-ink-muted" aria-live="polite">
            {progress}% complete
          </span>
        )}
      </div>
      <ol className="grid grid-cols-1 gap-px overflow-hidden rounded-b-xl bg-line sm:grid-cols-3 xl:grid-cols-6">
        {stages.map((name, i) => {
          const m = byName.get(name);
          const failed = m?.status === "FAILED";
          const done = m?.status === "COMPLETED";
          const active = loading && !m && (running ? name === running : !metrics?.length);
          return (
            <li
              key={name}
              className="relative bg-surface px-4 py-3"
              title={m?.error ?? undefined}
              data-stage={name}
              data-state={m ? m.status.toLowerCase() : active ? "running" : "pending"}
            >
              <div className="flex items-center gap-2">
                {failed ? (
                  <XCircle className="h-4 w-4 shrink-0 text-fail" />
                ) : done ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-ok" />
                ) : active ? (
                  <Loader2 className="h-4 w-4 shrink-0 animate-spin text-accent" />
                ) : (
                  <CircleDashed className="h-4 w-4 shrink-0 text-ink-faint" />
                )}
                <span className="text-[11px] font-mono text-ink-faint">0{i + 1}</span>
              </div>
              <div className="mt-1.5 text-[13px] font-medium">{STAGE_LABELS[name] ?? name}</div>
              <div className="mt-0.5 font-mono text-[11px] text-ink-muted">
                {m ? formatMs(m.duration_ms) : active ? "running…" : loading ? "queued" : "—"}
              </div>
              {m && (
                <div className="mt-2 h-1 overflow-hidden rounded-full bg-line">
                  <div
                    className={`h-full rounded-full ${failed ? "bg-fail" : "bg-accent/70"}`}
                    style={{ width: `${Math.max(4, (m.duration_ms / maxMs) * 100)}%` }}
                  />
                </div>
              )}
              {failed && m?.error && <div className="mt-1.5 line-clamp-2 text-[11px] text-fail">{m.error}</div>}
              {active && (
                <div className="absolute inset-x-0 bottom-0 h-0.5 overflow-hidden">
                  <div className="animate-scan h-full w-1/4 bg-accent" />
                </div>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
