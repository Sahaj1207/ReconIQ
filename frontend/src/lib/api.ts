import { UNAUTHORIZED_EVENT, loadSession } from "./session";
import type {
  AuditEvent,
  AuthConfig,
  Capabilities,
  Me,
  Role,
  Session,
  User,
  HealthResponse,
  InvestigationJob,
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
  const session = loadSession();
  if (session) return { Authorization: `Bearer ${session.access_token}` };
  const key = getApiKey();
  return key ? { "X-API-Key": key } : {};
}

async function errorFrom(res: Response, sentToken: string | null): Promise<ApiError> {
  let detail = `Request failed with status ${res.status}`;
  try {
    const body = await res.json();
    if (typeof body.detail === "string") detail = body.detail;
    else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
  } catch {
    // Non-JSON error body; keep the generic message.
  }
  // Only a rejection of the token we actually sent may end the session; a stale request from a
  // previous session (or an anonymous call) must not sign out whoever is signed in now.
  if (res.status === 401 && sentToken) window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT, { detail: sentToken }));
  return new ApiError(detail, res.status);
}

async function send(path: string, init: RequestInit = {}): Promise<Response> {
  let res: Response;
  const sentToken = loadSession()?.access_token ?? null;
  try {
    res = await fetch(`${API}${path}`, { ...init, headers: { ...authHeaders(), ...init.headers } });
  } catch {
    throw new ApiError("Cannot reach the ReconIQ API. Is the backend running on port 8000?");
  }
  if (!res.ok) throw await errorFrom(res, sentToken);
  return res;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await send(path, init)).json() as Promise<T>;
}

export const getHealth = () => json<HealthResponse>("/health");
export const getCapabilities = () => json<Capabilities>("/system/capabilities");
export const getStats = () => json<InvestigationStats>("/investigations/stats");
export const getInvestigation = (id: string) => json<InvestigationResult>(`/investigations/${encodeURIComponent(id)}`);

// --- Background jobs: start, then poll for per-stage progress ---

export function startInvestigationJob(payload: InvestigationRequest): Promise<InvestigationJob> {
  return json<InvestigationJob>("/evidence/jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function startFileInvestigationJob(file: File, refang: boolean): Promise<InvestigationJob> {
  const form = new FormData();
  form.append("file", file);
  form.append("refang", String(refang));
  return json<InvestigationJob>("/evidence/jobs/file", { method: "POST", body: form });
}

export const getJob = (id: string) => json<InvestigationJob>(`/jobs/${encodeURIComponent(id)}`);

export function listInvestigations(params: { limit?: number; offset?: number; severity?: string; q?: string; mine?: boolean }) {
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

// --- Authentication & administration ---

const post = <T>(path: string, body: unknown, method = "POST") =>
  json<T>(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export const getAuthConfig = () => json<AuthConfig>("/auth/config");
export const getMe = () => json<Me>("/auth/me");
export const login = (email: string, password: string) => post<Session>("/auth/login", { email, password });
export const register = (email: string, password: string, name: string) =>
  post<Session>("/auth/register", { email, password, name });

export async function changePassword(current_password: string, new_password: string): Promise<void> {
  await send("/auth/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password, new_password }),
  });
}

export const listUsers = () => json<{ total: number; items: User[] }>("/users");
export const createUser = (body: { email: string; name: string; password: string; role: Role }) => post<User>("/users", body);
export const updateUser = (id: string, body: Partial<{ name: string; role: Role; is_active: boolean; password: string }>) =>
  post<User>(`/users/${encodeURIComponent(id)}`, body, "PATCH");
export async function deleteUser(id: string): Promise<void> {
  await send(`/users/${encodeURIComponent(id)}`, { method: "DELETE" });
}
export function listAudit(params: { limit?: number; offset?: number; action?: string }) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => v !== undefined && v !== "" && qs.set(k, String(v)));
  return json<{ total: number; items: AuditEvent[] }>(`/audit?${qs}`);
}
