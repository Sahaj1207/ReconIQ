import { useState } from "react";
import { Bot, CheckCircle2, CircleSlash, ExternalLink, KeyRound, ListChecks, Radar, Server } from "lucide-react";
import { getApiKey, setApiKey } from "../lib/api";
import type { Capabilities } from "../lib/types";
import { SeverityBadge } from "../components/SeverityBadge";

export function SystemPage({ caps, error, onKeySaved }: { caps: Capabilities | null; error: string | null; onKeySaved: () => void }) {
  return (
    <div className="mx-auto grid max-w-[1200px] gap-5 lg:grid-cols-2">
      <ApiAccess authEnabled={caps?.auth_enabled} error={error} onSaved={onKeySaved} />
      {caps && (
        <>
          <Overview caps={caps} />
          <Providers caps={caps} />
          <Rules caps={caps} />
        </>
      )}
    </div>
  );
}

function ApiAccess({ authEnabled, error, onSaved }: { authEnabled?: boolean; error: string | null; onSaved: () => void }) {
  const [key, setKey] = useState(getApiKey());
  const [saved, setSaved] = useState(false);
  return (
    <section className="card lg:col-span-2">
      <div className="card-header">
        <h2 className="card-title"><KeyRound className="h-4 w-4 text-accent" /> API access</h2>
        {authEnabled !== undefined && (
          <span className="chip bg-surface-2 text-ink-muted">{authEnabled ? "Authentication required" : "Authentication disabled"}</span>
        )}
      </div>
      <div className="flex flex-col gap-3 p-5 sm:flex-row sm:items-end">
        <label className="flex-1">
          <span className="text-[12px] text-ink-muted">API key (stored in this browser only)</span>
          <input
            type="password"
            value={key}
            onChange={(e) => { setKey(e.target.value); setSaved(false); }}
            placeholder={authEnabled === false ? "Not required by this server" : "Paste a key from API_KEYS"}
            className="mt-1 w-full rounded-lg border border-line bg-canvas/60 px-3 py-2 font-mono text-[13px] text-ink placeholder:text-ink-faint focus:border-accent/60 focus:outline-none"
          />
        </label>
        <button
          type="button"
          className="btn-primary"
          onClick={() => { setApiKey(key.trim()); setSaved(true); onSaved(); }}
        >
          {saved ? <CheckCircle2 className="h-4 w-4" /> : null} {saved ? "Saved" : "Save key"}
        </button>
      </div>
      {error && <p className="px-5 pb-4 text-[12px] text-fail">{error}</p>}
    </section>
  );
}

function Overview({ caps }: { caps: Capabilities }) {
  const rows: [string, React.ReactNode][] = [
    ["Version", `v${caps.version} · ${caps.environment}`],
    ["AI analyst", caps.analyst.mode === "claude" ? `Claude (${caps.analyst.model})` : "Deterministic template — set ANTHROPIC_API_KEY to enable Claude"],
    ["History", caps.persistence ? "Investigations are saved" : "Persistence disabled"],
    ["Rate limit", caps.rate_limit_per_minute ? `${caps.rate_limit_per_minute} requests / minute / client` : "Disabled"],
    ["Uploads", `Up to ${caps.ingestion.max_upload_mb} MB`],
    ["QR decoding", caps.ingestion.qr_decoding ? "Available" : "Unavailable (install opencv-python-headless)"],
    ["OCR", caps.ingestion.ocr ? "Available" : "Unavailable (install tesseract-ocr + pytesseract)"],
  ];
  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title"><Server className="h-4 w-4 text-accent" /> Deployment</h2>
        <Bot className="h-4 w-4 text-ink-faint" />
      </div>
      <dl className="divide-y divide-line px-5 py-2">
        {rows.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[120px_minmax(0,1fr)] gap-3 py-2 text-[13px]">
            <dt className="text-ink-faint">{k}</dt>
            <dd className="text-ink">{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function Providers({ caps }: { caps: Capabilities }) {
  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title"><Radar className="h-4 w-4 text-accent" /> Threat intelligence</h2>
        <span className="chip bg-surface-2 text-ink-muted">{caps.threat_intel.filter((p) => p.enabled).length} of {caps.threat_intel.length} enabled</span>
      </div>
      <ul className="divide-y divide-line">
        {caps.threat_intel.map((p) => (
          <li key={p.name} className="flex items-start gap-3 px-5 py-3">
            {p.enabled ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" /> : <CircleSlash className="mt-0.5 h-4 w-4 shrink-0 text-ink-faint" />}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-[13px] font-medium">
                {p.name}
                <a href={p.docs_url} target="_blank" rel="noreferrer" className="text-ink-faint hover:text-accent" aria-label={`${p.name} documentation`}>
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
              <div className="text-[11.5px] text-ink-faint">
                {p.artifact_types.join(", ")} ·{" "}
                {p.requires_key ? (p.enabled ? "key configured" : <>set <code className="font-mono">{p.key_setting}</code></>) : "no key needed"}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Rules({ caps }: { caps: Capabilities }) {
  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title"><ListChecks className="h-4 w-4 text-accent" /> Detection rules</h2>
        <span className="chip bg-surface-2 text-ink-muted">{caps.rules.length} deterministic rules</span>
      </div>
      <ul className="max-h-[420px] divide-y divide-line overflow-y-auto">
        {caps.rules.map((r) => (
          <li key={r.id} className="flex items-center gap-3 px-5 py-2">
            <span className="w-24 shrink-0 font-mono text-[11px] text-ink-faint">{r.id}</span>
            <span className="min-w-0 flex-1 truncate text-[13px]">{r.name}</span>
            <SeverityBadge severity={r.severity} />
            <span className="w-8 text-right font-mono text-[12px] tabular-nums text-ink-muted">{r.weight}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
