import { Loader2, Radar, Trash2 } from "lucide-react";
import { SAMPLES } from "../lib/samples";

interface Props {
  text: string;
  refang: boolean;
  loading: boolean;
  onTextChange: (text: string) => void;
  onRefangChange: (refang: boolean) => void;
  onSubmit: () => void;
}

const MAX_CHARS = 500_000;

export function InputPanel({ text, refang, loading, onTextChange, onRefangChange, onSubmit }: Props) {
  const canSubmit = text.trim().length > 0 && !loading;

  return (
    <section className="card flex flex-col">
      <div className="card-header">
        <h2 className="card-title">
          <Radar className="h-4 w-4 text-accent" />
          New investigation
        </h2>
        {text && (
          <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={() => onTextChange("")}>
            <Trash2 className="h-3.5 w-3.5" /> Clear
          </button>
        )}
      </div>

      <div className="flex flex-col gap-3 p-4">
        <div>
          <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-ink-faint">Load a sample</div>
          <div className="flex flex-wrap gap-2">
            {SAMPLES.map((s) => (
              <button
                key={s.id}
                type="button"
                title={s.description}
                onClick={() => onTextChange(s.text)}
                className="rounded-md border border-line bg-surface-2 px-2.5 py-1 text-xs text-ink-muted transition-colors hover:border-accent/50 hover:text-ink"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <label htmlFor="evidence-input" className="sr-only">
          Evidence text
        </label>
        <textarea
          id="evidence-input"
          value={text}
          onChange={(e) => onTextChange(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && canSubmit) onSubmit();
          }}
          maxLength={MAX_CHARS}
          spellCheck={false}
          placeholder="Paste an email, alert, log excerpt or any text containing indicators. Defanged notation like hxxps://evil[.]com and user[at]domain[dot]com is supported."
          className="min-h-[260px] w-full resize-y rounded-lg border border-line bg-canvas/70 p-3 font-mono text-[12.5px] leading-relaxed text-ink placeholder:text-ink-faint focus:border-accent/60 focus:outline-none"
        />

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="flex cursor-pointer select-none items-center gap-2 text-xs text-ink-muted">
            <input
              type="checkbox"
              checked={refang}
              onChange={(e) => onRefangChange(e.target.checked)}
              className="h-3.5 w-3.5 accent-cyan-400"
            />
            Refang defanged indicators
          </label>
          <span className="font-mono text-[11px] text-ink-faint">{text.length.toLocaleString()} chars</span>
        </div>

        <button type="button" className="btn-primary w-full" disabled={!canSubmit} onClick={onSubmit}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
          {loading ? "Investigating…" : "Run investigation"}
          {!loading && <kbd className="ml-1 rounded bg-slate-950/20 px-1.5 text-[10px] font-medium">Ctrl ↵</kbd>}
        </button>
      </div>
    </section>
  );
}
