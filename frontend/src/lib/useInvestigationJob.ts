import { useCallback, useEffect, useRef, useState } from "react";
import { getInvestigation, getJob } from "./api";
import type { InvestigationJob, InvestigationResult } from "./types";

const POLL_MS = 600;

/** Thrown to an abandoned run when a newer one starts; callers should ignore it. */
export class JobSuperseded extends Error {}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Starts a background investigation and polls it until it finishes, exposing the job's live
 * per-stage progress. Starting a new run abandons the previous one's polling.
 */
export function useInvestigationJob(pollMs = POLL_MS) {
  const [job, setJob] = useState<InvestigationJob | null>(null);
  const [running, setRunning] = useState(false);
  const runId = useRef(0);

  useEffect(() => () => void runId.current++, []); // stop polling on unmount

  const run = useCallback(
    async (start: () => Promise<InvestigationJob>): Promise<InvestigationResult> => {
      const id = ++runId.current;
      const current = () => id === runId.current;
      setRunning(true);
      setJob(null);
      try {
        let state = await start();
        while (current()) {
          setJob(state);
          if (state.status === "succeeded" && state.investigation_id) return await getInvestigation(state.investigation_id);
          if (state.status === "failed") throw new Error(state.error ?? "Investigation failed");
          await sleep(pollMs);
          if (current()) state = await getJob(state.job_id);
        }
        throw new JobSuperseded("Investigation superseded");
      } finally {
        if (current()) setRunning(false);
      }
    },
    [pollMs],
  );

  return { job, running, run };
}
