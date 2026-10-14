import { Brain, Crosshair, Radar, ShieldCheck } from "lucide-react";

const STEPS = [
  { icon: Radar, title: "Collect & normalize", text: "Extract URLs, domains, IPs, emails and phone numbers — defanged or not." },
  { icon: ShieldCheck, title: "Validate", text: "RFC checks, TLD verification and private-range classification." },
  { icon: Crosshair, title: "Enrich", text: "Query threat intelligence providers such as VirusTotal." },
  { icon: Brain, title: "Score deterministically", text: "Explainable rules produce a 0–100 score with a full audit trail." },
];

export function EmptyState() {
  return (
    <section className="card flex flex-col items-center px-6 py-12 text-center">
      <div className="grid h-14 w-14 place-items-center rounded-2xl bg-accent/10 ring-1 ring-accent/25">
        <Radar className="h-7 w-7 text-accent" />
      </div>
      <h2 className="mt-4 text-lg font-semibold">Start an investigation</h2>
      <p className="mt-1 max-w-md text-sm text-ink-muted">
        Paste suspicious content on the left, or load a sample. Every verdict is produced by deterministic rules — never by
        an AI model.
      </p>
      <div className="mt-8 grid w-full max-w-3xl gap-3 text-left sm:grid-cols-2">
        {STEPS.map(({ icon: Icon, title, text }, i) => (
          <div key={title} className="flex gap-3 rounded-lg border border-line bg-canvas/40 p-3">
            <div className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-surface-2 text-ink-muted">
              <Icon className="h-4 w-4" />
            </div>
            <div>
              <div className="text-[13px] font-medium">
                <span className="mr-1.5 font-mono text-[11px] text-ink-faint">0{i + 1}</span>
                {title}
              </div>
              <div className="mt-0.5 text-[12px] text-ink-muted">{text}</div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
