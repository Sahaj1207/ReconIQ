import { useRef, useState } from "react";
import { FileUp, Loader2, Radar, Trash2, Type, X } from "lucide-react";
import { SAMPLES } from "../lib/samples";
import { formatBytes } from "../lib/format";

export type InputMode = "text" | "file";

interface Props {
  mode: InputMode;
  text: string;
  file: File | null;
  refang: boolean;
  loading: boolean;
  maxUploadMb: number;
  onModeChange: (mode: InputMode) => void;
  onTextChange: (text: string) => void;
  onFileChange: (file: File | null) => void;
  onRefangChange: (refang: boolean) => void;
  onSubmit: () => void;
}

const MAX_CHARS = 500_000;
const ACCEPT = ".eml,.pdf,.png,.jpg,.jpeg,.gif,.webp,.bmp,.apk,.txt,.log,.csv,.json,.html,.htm,.exe,.zip,.docm,.xlsm,*/*";

export function InputPanel(props: Props) {
  const { mode, text, file, refang, loading, maxUploadMb } = props;
  const fileOk = file !== null && file.size <= maxUploadMb * 1024 * 1024;
  const canSubmit = !loading && (mode === "text" ? text.trim().length > 0 : fileOk);

  return (
    <section className="card flex flex-col">
      <div className="card-header">
        <h2 className="card-title">
          <Radar className="h-4 w-4 text-accent" />
          New investigation
        </h2>
        <div role="tablist" className="flex rounded-lg border border-line p-0.5 text-[11px]">
          {([
            { id: "text", label: "Text", icon: Type },
            { id: "file", label: "File", icon: FileUp },
          ] as const).map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              role="tab"
              aria-selected={mode === id}
              type="button"
              onClick={() => props.onModeChange(id)}
              className={`flex items-center gap-1 rounded-md px-2.5 py-1 font-medium ${mode === id ? "bg-surface-2 text-ink" : "text-ink-faint hover:text-ink-muted"}`}
            >
              <Icon className="h-3.5 w-3.5" /> {label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-3 p-4">
        {mode === "text" ? <TextInput {...props} canSubmit={canSubmit} /> : <FileInput {...props} />}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="flex cursor-pointer select-none items-center gap-2 text-xs text-ink-muted">
            <input
              type="checkbox"
              checked={refang}
              onChange={(e) => props.onRefangChange(e.target.checked)}
              className="h-3.5 w-3.5 accent-cyan-400"
            />
            Refang defanged indicators
          </label>
          <span className="font-mono text-[11px] text-ink-faint">
            {mode === "text" ? `${text.length.toLocaleString()} chars` : `max ${maxUploadMb} MB`}
          </span>
        </div>

        <button type="button" className="btn-primary w-full" disabled={!canSubmit} onClick={props.onSubmit}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
          {loading ? "Investigating…" : mode === "file" ? "Investigate file" : "Run investigation"}
          {!loading && mode === "text" && <kbd className="ml-1 rounded bg-slate-950/20 px-1.5 text-[10px] font-medium">Ctrl ↵</kbd>}
        </button>
      </div>
    </section>
  );
}

function TextInput({ text, onTextChange, onSubmit, canSubmit }: Props & { canSubmit: boolean }) {
  return (
    <>
      <div>
        <div className="mb-2 flex items-center justify-between">
          <span className="text-[11px] font-medium uppercase tracking-wider text-ink-faint">Load a sample</span>
          {text && (
            <button type="button" className="btn-ghost px-1.5 py-0.5 text-[11px]" onClick={() => onTextChange("")}>
              <Trash2 className="h-3 w-3" /> Clear
            </button>
          )}
        </div>
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
    </>
  );
}

function FileInput({ file, onFileChange, maxUploadMb }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const tooBig = file !== null && file.size > maxUploadMb * 1024 * 1024;

  return (
    <>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const dropped = e.dataTransfer.files?.[0];
          if (dropped) onFileChange(dropped);
        }}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && inputRef.current?.click()}
        role="button"
        tabIndex={0}
        className={`flex min-h-[200px] cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-6 text-center transition-colors ${
          dragging ? "border-accent bg-accent/8" : "border-line-strong bg-canvas/50 hover:border-accent/50"
        }`}
      >
        <FileUp className="h-7 w-7 text-accent" />
        <div className="text-sm font-medium">Drop a file or click to browse</div>
        <div className="max-w-xs text-[12px] text-ink-faint">
          Emails (.eml), PDFs, screenshots and QR images, Android APKs, logs — or any binary to fingerprint and hash-check.
        </div>
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPT}
          className="hidden"
          onChange={(e) => onFileChange(e.target.files?.[0] ?? null)}
        />
      </div>
      {file && (
        <div className={`flex items-center gap-3 rounded-lg border px-3 py-2 ${tooBig ? "border-fail/40 bg-fail/8" : "border-line bg-surface-2/60"}`}>
          <FileUp className="h-4 w-4 shrink-0 text-ink-muted" />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px]">{file.name}</div>
            <div className={`text-[11px] ${tooBig ? "text-fail" : "text-ink-faint"}`}>
              {formatBytes(file.size)}
              {tooBig && ` — exceeds the ${maxUploadMb} MB limit`}
            </div>
          </div>
          <button type="button" aria-label="Remove file" className="rounded p-1 text-ink-faint hover:text-ink" onClick={() => onFileChange(null)}>
            <X className="h-4 w-4" />
          </button>
        </div>
      )}
    </>
  );
}
