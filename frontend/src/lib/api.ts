import type {
  Capabilities,
  HealthResponse,
  InvestigationList,
  InvestigationRequest,
  InvestigationResult,
  InvestigationStats,
  ReportFormat,
} from "./types";

const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
const API = `${BASE_URL}/api/v1`;
const KEY_STORAGE = "reconiq.apiKey";

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
  }
}

export function getApiKey(): string {
  try {
    return localStorage.getItem(KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setApiKey(key: string): void {
  try {
    if (key) localStorage.setItem(KEY_STORAGE, key);
    else localStorage.removeItem(KEY_STORAGE);
  } catch {
    // Storage unavailable; the key simply won't persist.
  }
}

function authHeaders(): Record<string, string> {
  const key = getApiKey();
  return key ? { "X-API-Key": key } : {};
}

async function errorFrom(res: Response): Promise<ApiError> {
  let detail = `Request failed with status ${res.status}`;
  try {
    const body = await res.json();
    if (typeof body.detail === "string") detail = body.detail;
    else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
  } catch {
    // Non-JSON error body; keep the generic message.
  }
  if (res.status === 401) detail = "This API requires a key. Add it under System → API access.";
  return new ApiError(detail, res.status);
}

async function send(path: string, init: RequestInit = {}): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { ...init, headers: { ...authHeaders(), ...init.headers } });
  } catch {
    throw new ApiError("Cannot reach the ReconIQ API. Is the backend running on port 8000?");
  }
  if (!res.ok) throw await errorFrom(res);
  return res;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await send(path, init)).json() as Promise<T>;
}

export const getHealth = () => json<HealthResponse>("/health");
export const getCapabilities = () => json<Capabilities>("/system/capabilities");
export const getStats = () => json<InvestigationStats>("/investigations/stats");
export const getInvestigation = (id: string) => json<InvestigationResult>(`/investigations/${encodeURIComponent(id)}`);

export function investigate(payload: InvestigationRequest): Promise<InvestigationResult> {
  return json<InvestigationResult>("/evidence/investigate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function investigateFile(file: File, refang: boolean): Promise<InvestigationResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("refang", String(refang));
  return json<InvestigationResult>("/evidence/investigate/file", { method: "POST", body: form });
}

export function listInvestigations(params: { limit?: number; offset?: number; severity?: string; q?: string }) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") qs.set(k, String(v));
  });
  return json<InvestigationList>(`/investigations?${qs}`);
}

export async function deleteInvestigation(id: string): Promise<void> {
  await send(`/investigations/${encodeURIComponent(id)}`, { method: "DELETE" });
}

const EXTENSIONS: Record<ReportFormat, string> = { json: "json", stix: "stix.json", markdown: "md", pdf: "pdf" };

/** Fetches a report with auth headers and triggers a browser download. */
export async function downloadReport(id: string, format: ReportFormat): Promise<void> {
  const res = await send(`/investigations/${encodeURIComponent(id)}/report?format=${format}`);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `reconiq-${id.slice(0, 8)}.${EXTENSIONS[format]}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
