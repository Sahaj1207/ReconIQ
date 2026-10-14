import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { InvestigationJob, JobStatus } from "./types";

vi.mock("./api", () => ({ getJob: vi.fn(), getInvestigation: vi.fn() }));
const api = await import("./api");
const { JobSuperseded, useInvestigationJob } = await import("./useInvestigationJob");

function job(status: JobStatus, progress: number, extra: Partial<InvestigationJob> = {}): InvestigationJob {
  return {
    job_id: "job-1",
    created_at: "2026-10-14T10:00:00+00:00",
    updated_at: "2026-10-14T10:00:00+00:00",
    status,
    source_type: "raw_text",
    source_name: null,
    stages: [],
    current_stage: null,
    progress,
    investigation_id: null,
    error: null,
    ...extra,
  };
}

describe("useInvestigationJob", () => {
  beforeEach(() => vi.mocked(api.getJob).mockReset());

  it("polls until the job succeeds, exposing progress, then loads the result", async () => {
    vi.mocked(api.getJob)
      .mockResolvedValueOnce(job("running", 50, { current_stage: "threat_intelligence" }))
      .mockResolvedValueOnce(job("succeeded", 100, { investigation_id: "inv-9" }));
    vi.mocked(api.getInvestigation).mockResolvedValue({ investigation_id: "inv-9" } as never);
    const { result } = renderHook(() => useInvestigationJob(150));

    let pending!: Promise<unknown>;
    act(() => {
      pending = result.current.run(async () => job("queued", 0));
    });
    await waitFor(() => expect(result.current.job?.progress).toBe(0));
    await waitFor(() => expect(result.current.job?.current_stage).toBe("threat_intelligence"));
    expect(result.current.running).toBe(true);

    let outcome: unknown;
    await act(async () => {
      outcome = await pending;
    });
    expect(outcome).toEqual({ investigation_id: "inv-9" });
    expect(api.getInvestigation).toHaveBeenCalledWith("inv-9");
    expect(result.current.job?.progress).toBe(100);
    expect(result.current.running).toBe(false);
  });

  it("rejects with the job's error when it fails", async () => {
    vi.mocked(api.getJob).mockResolvedValueOnce(job("failed", 33, { error: "The investigation stopped responding" }));
    const { result } = renderHook(() => useInvestigationJob(1));
    await act(async () => {
      await expect(result.current.run(async () => job("queued", 0))).rejects.toThrow("stopped responding");
    });
    expect(result.current.running).toBe(false);
  });

  it("abandons an earlier run when a new one starts", async () => {
    vi.mocked(api.getJob).mockResolvedValue(job("running", 10));
    const { result } = renderHook(() => useInvestigationJob(5));
    let first!: Promise<unknown>;
    act(() => {
      first = result.current.run(async () => job("queued", 0)).catch((e) => e);
    });
    vi.mocked(api.getJob).mockResolvedValue(job("succeeded", 100, { investigation_id: "inv-2" }));
    vi.mocked(api.getInvestigation).mockResolvedValue({ investigation_id: "inv-2" } as never);
    await act(async () => {
      await result.current.run(async () => job("queued", 0, { job_id: "job-2" }));
    });
    expect(await first).toBeInstanceOf(JobSuperseded);
  });
});
