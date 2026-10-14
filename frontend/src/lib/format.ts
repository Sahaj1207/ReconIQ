import type { ArtifactCategory, Severity } from "./types";

export const CATEGORY_LABELS: Record<ArtifactCategory, string> = {
  urls: "URLs",
  domains: "Domains",
  ipv4: "IPv4",
  ipv6: "IPv6",
  emails: "Emails",
  phone_numbers: "Phone numbers",
};

export const CATEGORY_ORDER: ArtifactCategory[] = ["urls", "domains", "ipv4", "ipv6", "emails", "phone_numbers"];

export const STAGE_LABELS: Record<string, string> = {
  evidence_collection: "Evidence collection",
  normalization: "Normalization",
  validation: "Validation",
  threat_intelligence: "Threat intelligence",
  risk_assessment: "Risk assessment",
};

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

interface SeverityStyle {
  label: string;
  text: string;
  bg: string;
  ring: string;
  stroke: string;
}

// Static class strings so Tailwind can see them at build time.
const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  CRITICAL: { label: "Critical", text: "text-sev-critical", bg: "bg-sev-critical/12", ring: "ring-sev-critical/35", stroke: "var(--color-sev-critical)" },
  HIGH: { label: "High", text: "text-sev-high", bg: "bg-sev-high/12", ring: "ring-sev-high/35", stroke: "var(--color-sev-high)" },
  MEDIUM: { label: "Medium", text: "text-sev-medium", bg: "bg-sev-medium/12", ring: "ring-sev-medium/35", stroke: "var(--color-sev-medium)" },
  LOW: { label: "Low", text: "text-sev-low", bg: "bg-sev-low/12", ring: "ring-sev-low/35", stroke: "var(--color-sev-low)" },
  INFORMATIONAL: { label: "Info", text: "text-sev-info", bg: "bg-sev-info/12", ring: "ring-sev-info/35", stroke: "var(--color-sev-info)" },
};

export function severityStyle(severity: string | undefined | null): SeverityStyle {
  const key = (severity ?? "").toUpperCase() as Severity;
  return SEVERITY_STYLES[key] ?? SEVERITY_STYLES.INFORMATIONAL;
}

export function formatMs(ms: number): string {
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function formatRelativeTime(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

export function humanizeKey(key: string): string {
  return key.replace(/^is_/, "").replace(/_/g, " ");
}

/** Defang an indicator for safe display/copy (https -> hxxps, . -> [.]). */
export function defang(value: string): string {
  return value.replace(/^http/i, "hxxp").replace(/\./g, "[.]").replace(/@/g, "[at]");
}
