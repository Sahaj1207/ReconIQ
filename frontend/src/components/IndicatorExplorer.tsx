import { useMemo, useState } from "react";
import { CheckCircle2, Crosshair, ShieldAlert, ShieldOff, ShieldQuestion, XCircle } from "lucide-react";
import type { ArtifactCategory, InvestigationResult, ThreatIntelResponse, ValidationResult } from "../lib/types";
import { CATEGORY_LABELS, CATEGORY_ORDER, defang, formatPercent, humanizeKey } from "../lib/format";
import { CopyButton } from "./CopyButton";

interface Row {
  artifact: string;
  validation?: ValidationResult;
  intel: ThreatIntelResponse[];
}

function buildRows(result: InvestigationResult, category: ArtifactCategory): Row[] {
  const artifacts = result.normalized_evidence[category] ?? result.evidence[category] ?? [];
  const validations = result.validation_results[category] ?? [];
  const intel = result.threat_intelligence[category] ?? [];
  return artifacts.map((artifact) => ({
    artifact,
    validation: validations.find((v) => v.artifact === artifact),
    intel: intel.filter((i) => i.artifact === artifact),
  }));
}

/** Surface the properties an analyst cares about; skip noisy false flags. */
function propertyChips(props: Record<string, unknown> = {}): string[] {
  const chips: string[] = [];
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === "") continue;
    if (typeof value === "boolean") {
      if (value && key !== "is_valid" && key !== "is_possible") chips.push(humanizeKey(key));
      continue;
    }
    if (["e164_format", "local_part", "hostname"].includes(key)) continue;
    if (key === "subdomain_count" && value === 0) continue;
    chips.push(`${humanizeKey(key)}: ${String(value)}`);
  }
  return chips;
}

export function IndicatorExplorer({ result }: { result: InvestigationResult }) {
  const available = CATEGORY_ORDER.filter((c) => (result.normalized_evidence[c] ?? result.evidence[c] ?? []).length > 0);
  const [active, setActive] = useState<ArtifactCategory | null>(null);
  const current = active && available.includes(active) ? active : available[0];
  const rows = useMemo(() => (current ? buildRows(result, current) : []), [result, current]);

  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Crosshair className="h-4 w-4 text-accent" />
          Indicators of compromise
        </h2>
      </div>

      {available.length === 0 ? (
        <div className="px-5 py-6 text-sm text-ink-muted">No indicators were extracted from the input.</div>
      ) : (
        <>
          <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-line px-3 pt-2">
            {available.map((c) => {
              const count = (result.normalized_evidence[c] ?? result.evidence[c] ?? []).length;
              const selected = c === current;
              return (
                <button
                  key={c}
                  role="tab"
                  aria-selected={selected}
                  onClick={() => setActive(c)}
                  className={`-mb-px flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium transition-colors ${
                    selected ? "border-accent text-ink" : "border-transparent text-ink-faint hover:text-ink-muted"
                  }`}
                >
                  {CATEGORY_LABELS[c]}
                  <span className={`rounded px-1.5 text-[10px] ${selected ? "bg-accent/15 text-accent" : "bg-surface-2"}`}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          <ul className="divide-y divide-line">
            {rows.map((row) => (
              <IndicatorRow key={row.artifact} row={row} />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function IndicatorRow({ row }: { row: Row }) {
  const { validation, intel } = row;
  const chips = propertyChips(validation?.properties);
  const invalidReason = validation && !validation.valid ? (validation.reason as string | undefined) ?? "Failed validation" : null;

  return (
    <li className="grid gap-3 px-5 py-3 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-start">
      <div className="min-w-0">
        <div className="flex items-center gap-1.5">
          {validation ? (
            validation.valid ? (
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-ok" aria-label="Valid" />
            ) : (
              <XCircle className="h-3.5 w-3.5 shrink-0 text-fail" aria-label="Invalid" />
            )
          ) : null}
          <span className="truncate font-mono text-[13px] text-ink" title={row.artifact}>
            {row.artifact}
          </span>
          <CopyButton value={row.artifact} label="Copy" />
          <button
            type="button"
            onClick={() => navigator.clipboard?.writeText(defang(row.artifact)).catch(() => undefined)}
            className="rounded px-1 text-[10px] font-medium text-ink-faint hover:bg-surface-2 hover:text-ink"
            title="Copy defanged"
          >
            defang
          </button>
        </div>
        {invalidReason && <div className="mt-1 text-[12px] text-fail">{invalidReason}</div>}
        {chips.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {chips.map((c) => (
              <span key={c} className="chip bg-surface-2 text-ink-muted">
                {c}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-1.5 lg:justify-end">
        {intel.length === 0 ? (
          <span className="chip bg-surface-2 text-ink-faint">No intel lookup</span>
        ) : (
          intel.map((i) => <IntelChip key={i.provider} intel={i} />)
        )}
      </div>
    </li>
  );
}

function IntelChip({ intel }: { intel: ThreatIntelResponse }) {
  const malicious = intel.threat_indicators.length > 0;
  if (intel.status !== "SUCCESS" && intel.status !== "PARTIAL") {
    return (
      <span className="chip bg-surface-2 text-ink-faint" title={intel.error_message ?? intel.status}>
        <ShieldOff className="h-3 w-3" />
        {intel.provider} · {intel.status.toLowerCase().replace("_", " ")}
      </span>
    );
  }
  if (malicious) {
    return (
      <span
        className="chip bg-sev-critical/12 text-sev-critical ring-1 ring-inset ring-sev-critical/30"
        title={intel.threat_indicators.map((t) => t.description ?? t.category).join("\n")}
      >
        <ShieldAlert className="h-3 w-3" />
        {intel.provider} · {intel.threat_indicators.length} flag{intel.threat_indicators.length === 1 ? "" : "s"} ·{" "}
        {formatPercent(intel.confidence)}
      </span>
    );
  }
  return (
    <span className="chip bg-ok/10 text-ok" title="No detections">
      <ShieldQuestion className="h-3 w-3" />
      {intel.provider} · clean
    </span>
  );
}
