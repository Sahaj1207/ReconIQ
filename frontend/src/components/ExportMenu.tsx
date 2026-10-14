import { useEffect, useRef, useState } from "react";
import { ChevronDown, Download, Loader2 } from "lucide-react";
import { downloadReport } from "../lib/api";
import type { ReportFormat } from "../lib/types";

const OPTIONS: { format: ReportFormat; label: string; hint: string }[] = [
  { format: "pdf", label: "PDF report", hint: "Executive summary, defanged" },
  { format: "markdown", label: "Markdown", hint: "For tickets and wikis" },
  { format: "stix", label: "STIX 2.1 bundle", hint: "For TIPs and SIEMs" },
  { format: "json", label: "Raw JSON", hint: "Complete result" },
];

export function ExportMenu({ investigationId }: { investigationId: string }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const pick = async (format: ReportFormat) => {
    setBusy(format);
    setError(null);
    try {
      await downloadReport(investigationId, format);
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div ref={ref} className="relative">
      <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <Download className="h-3.5 w-3.5" /> Export <ChevronDown className="h-3 w-3" />
      </button>
      {open && (
        <div className="absolute right-0 bottom-full z-30 mb-1 w-60 overflow-hidden rounded-lg border border-line-strong bg-surface shadow-xl shadow-black/40">
          {OPTIONS.map((o) => (
            <button
              key={o.format}
              type="button"
              onClick={() => pick(o.format)}
              disabled={busy !== null}
              className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-surface-2 disabled:opacity-60"
            >
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] text-ink">{o.label}</span>
                <span className="block text-[11px] text-ink-faint">{o.hint}</span>
              </span>
              {busy === o.format && <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />}
            </button>
          ))}
          {error && <div className="border-t border-line px-3 py-2 text-[11px] text-fail">{error}</div>}
        </div>
      )}
    </div>
  );
}
