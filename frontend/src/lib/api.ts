import type { HealthResponse, InvestigationRequest, InvestigationResult } from "./types";

const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
const API = `${BASE_URL}/api/v1`;

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch {
    throw new ApiError("Cannot reach the ReconIQ API. Is the backend running on port 8000?");
  }

  if (!res.ok) {
    let detail = `Request failed with status ${res.status}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    throw new ApiError(detail, res.status);
  }
  return res.json() as Promise<T>;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export function investigate(payload: InvestigationRequest): Promise<InvestigationResult> {
  return request<InvestigationResult>("/evidence/investigate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
