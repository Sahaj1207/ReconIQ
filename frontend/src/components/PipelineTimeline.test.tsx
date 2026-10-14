import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PipelineTimeline } from "./PipelineTimeline";
import type { StageMetric } from "../lib/types";

const stage = (stage_name: string, status: StageMetric["status"], duration_ms = 0, error: string | null = null): StageMetric => ({
  stage_name,
  status,
  duration_ms,
  error,
});

function states(container: HTMLElement) {
  return Object.fromEntries([...container.querySelectorAll("li[data-stage]")].map((li) => [li.getAttribute("data-stage"), li.getAttribute("data-state")]));
}

describe("PipelineTimeline", () => {
  it("shows live job progress: finished, running and queued stages", () => {
    const { container } = render(
      <PipelineTimeline
        loading
        progress={33}
        metrics={[
          stage("evidence_collection", "COMPLETED", 4.2),
          stage("normalization", "COMPLETED", 1.1),
          stage("validation", "RUNNING"),
          stage("threat_intelligence", "PENDING"),
        ]}
      />,
    );
    expect(states(container)).toEqual({
      evidence_collection: "completed",
      normalization: "completed",
      validation: "running",
      threat_intelligence: "pending",
    });
    expect(screen.getByText("33% complete")).toBeInTheDocument();
    expect(screen.getByText("running…")).toBeInTheDocument();
    expect(screen.getByText("queued")).toBeInTheDocument();
  });

  it("animates every default stage before the job has reported anything", () => {
    const { container } = render(<PipelineTimeline loading />);
    const all = Object.values(states(container));
    expect(all).toHaveLength(6);
    expect(new Set(all)).toEqual(new Set(["running"]));
  });

  it("renders a finished run with durations and stage errors", () => {
    const { container } = render(
      <PipelineTimeline metrics={[stage("evidence_collection", "COMPLETED", 12), stage("threat_intelligence", "FAILED", 3, "provider timeout")]} />,
    );
    expect(states(container)).toEqual({ evidence_collection: "completed", threat_intelligence: "failed" });
    expect(screen.getByText("provider timeout")).toBeInTheDocument();
    expect(screen.queryByText(/% complete/)).not.toBeInTheDocument();
  });
});
