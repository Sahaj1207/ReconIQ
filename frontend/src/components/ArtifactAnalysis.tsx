import { CheckCircle2, FileSearch, Mail, Paperclip, QrCode, ShieldAlert, Smartphone, XCircle } from "lucide-react";
import type { EmailAnalysis, FileAnalysis, IngestionAnalysis } from "../lib/types";
import { formatBytes } from "../lib/format";
import { CopyButton } from "./CopyButton";

const AUTH_OK = new Set(["pass"]);
const AUTH_BAD = new Set(["fail", "softfail", "permerror", "hardfail"]);

export function ArtifactAnalysis({ ingestion }: { ingestion: IngestionAnalysis }) {
  if (!ingestion?.email && !ingestion?.file) return null;
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      {ingestion.email && <EmailPanel email={ingestion.email} />}
      {ingestion.file && <FilePanel file={ingestion.file} compact={Boolean(ingestion.email)} />}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[110px_minmax(0,1fr)] gap-3 py-1.5 text-[13px]">
      <dt className="text-ink-faint">{label}</dt>
      <dd className="min-w-0 break-words text-ink">{children}</dd>
    </div>
  );
}

function EmailPanel({ email }: { email: EmailAnalysis }) {
  const checks = ["spf", "dkim", "dmarc"];
  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Mail className="h-4 w-4 text-accent" />
          Email headers
        </h2>
      </div>
      <div className="p-5">
        <div className="mb-3 grid grid-cols-3 gap-2">
          {checks.map((c) => {
            const v = email.authentication?.[c];
            const ok = v && AUTH_OK.has(v);
            const bad = v && AUTH_BAD.has(v);
            return (
              <div
                key={c}
                className={`rounded-lg border px-3 py-2 ${bad ? "border-fail/40 bg-fail/8" : ok ? "border-ok/30 bg-ok/8" : "border-line bg-canvas/40"}`}
              >
                <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint">{c}</div>
                <div className={`mt-0.5 flex items-center gap-1 text-sm font-semibold ${bad ? "text-fail" : ok ? "text-ok" : "text-ink-muted"}`}>
                  {bad ? <XCircle className="h-3.5 w-3.5" /> : ok ? <CheckCircle2 className="h-3.5 w-3.5" /> : null}
                  {v ?? "absent"}
                </div>
              </div>
            );
          })}
        </div>
        <dl className="divide-y divide-line">
          <Row label="Subject">{email.subject || "—"}</Row>
          <Row label="From">
            {email.display_name && <span className="text-ink-muted">{email.display_name} </span>}
            <span className="font-mono text-[12px]">&lt;{email.from ?? "?"}&gt;</span>
          </Row>
          {email.reply_to && (
            <Row label="Reply-To">
              <span className={`font-mono text-[12px] ${email.reply_to.split("@")[1] !== email.from_domain ? "text-sev-medium" : ""}`}>
                {email.reply_to}
              </span>
            </Row>
          )}
          {email.return_path && <Row label="Return-Path"><span className="font-mono text-[12px]">{email.return_path}</span></Row>}
          {email.date && <Row label="Date">{email.date}</Row>}
          <Row label="Relay IPs">
            {email.received_ips.length ? <span className="font-mono text-[12px]">{email.received_ips.join(", ")}</span> : "—"}
          </Row>
          <Row label="Links">{email.links.length}</Row>
        </dl>
        {email.attachments.length > 0 && (
          <div className="mt-4">
            <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">
              <Paperclip className="h-3.5 w-3.5" /> Attachments
            </div>
            <ul className="space-y-1.5">
              {email.attachments.map((a) => (
                <li key={a.sha256} className="flex items-center gap-2 rounded-md border border-line bg-canvas/40 px-3 py-2 text-[12.5px]">
                  {a.dangerous ? <ShieldAlert className="h-4 w-4 shrink-0 text-fail" /> : <Paperclip className="h-4 w-4 shrink-0 text-ink-faint" />}
                  <span className="min-w-0 flex-1 truncate">{a.filename}</span>
                  <span className="text-[11px] text-ink-faint">{formatBytes(a.size)}</span>
                  {a.dangerous && <span className="chip bg-fail/12 text-fail">high-risk type</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

function FilePanel({ file, compact }: { file: FileAnalysis; compact: boolean }) {
  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title">
          <FileSearch className="h-4 w-4 text-accent" />
          File analysis
        </h2>
        {file.dangerous && <span className="chip bg-fail/12 text-fail">High-risk file type</span>}
      </div>
      <div className="p-5">
        <dl className="divide-y divide-line">
          <Row label="Name">{file.filename}</Row>
          <Row label="Type">
            {file.kind} · {file.mime} · {formatBytes(file.size)}
            {file.extension_mismatch && <span className="ml-2 chip bg-sev-medium/12 text-sev-medium">extension mismatch</span>}
          </Row>
          {!compact &&
            (["sha256", "sha1", "md5"] as const).map((h) => (
              <Row key={h} label={h.toUpperCase()}>
                <span className="flex items-center gap-1 font-mono text-[11.5px]">
                  <span className="truncate">{file[h]}</span>
                  <CopyButton value={file[h]} />
                </span>
              </Row>
            ))}
        </dl>

        {file.qr_payloads && (
          <SubSection icon={<QrCode className="h-3.5 w-3.5" />} title="QR codes">
            {file.qr_payloads.length ? (
              file.qr_payloads.map((p) => (
                <div key={p} className="break-all rounded-md border border-line bg-canvas/40 px-3 py-2 font-mono text-[12px]">{p}</div>
              ))
            ) : (
              <p className="text-[12.5px] text-ink-muted">No QR code detected.</p>
            )}
            {file.ocr && (
              <p className="text-[11.5px] text-ink-faint">
                OCR: {file.ocr.available ? `${file.ocr.characters} characters extracted` : file.ocr.note ?? "unavailable"}
              </p>
            )}
          </SubSection>
        )}

        {file.pdf && (
          <SubSection icon={<FileSearch className="h-3.5 w-3.5" />} title="PDF">
            <p className="text-[12.5px] text-ink-muted">
              {file.pdf.pages} page(s) · {file.pdf.links.length} link(s)
              {file.pdf.metadata?.Producer ? ` · produced by ${file.pdf.metadata.Producer}` : ""}
            </p>
            {file.pdf.active_content.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {file.pdf.active_content.map((m) => (
                  <span key={m} className="chip bg-fail/12 font-mono text-fail">{m}</span>
                ))}
              </div>
            ) : (
              <p className="text-[12px] text-ok">No JavaScript, launch or auto-open actions.</p>
            )}
          </SubSection>
        )}

        {file.apk && (
          <SubSection icon={<Smartphone className="h-3.5 w-3.5" />} title="Android package">
            <p className="font-mono text-[12.5px]">{file.apk.package ?? "unknown package"}</p>
            <p className="text-[12px] text-ink-muted">
              {file.apk.permissions.length} permission(s) · {file.apk.embedded_urls.length} embedded URL(s)
              {file.apk.has_native_code ? " · native code" : ""}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {file.apk.permissions.map((p) => {
                const bad = file.apk!.dangerous_permissions.includes(p);
                return (
                  <span key={p} className={`chip font-mono ${bad ? "bg-fail/12 text-fail" : "bg-surface-2 text-ink-muted"}`}>
                    {p.replace("android.permission.", "")}
                  </span>
                );
              })}
            </div>
          </SubSection>
        )}
      </div>
    </section>
  );
}

function SubSection({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="mt-4 space-y-2">
      <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">
        {icon} {title}
      </div>
      {children}
    </div>
  );
}
