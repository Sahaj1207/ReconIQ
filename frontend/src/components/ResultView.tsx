import type { InvestigationResult } from "../lib/types";
import { VerdictCard } from "./VerdictCard";
import { AnalystCard } from "./AnalystCard";
import { Notices } from "./Notices";
import { PipelineTimeline } from "./PipelineTimeline";
import { FindingsList } from "./FindingsList";
import { RuleAudit } from "./RuleAudit";
import { IndicatorExplorer } from "./IndicatorExplorer";
import { AttackPanel } from "./AttackPanel";
import { ArtifactAnalysis } from "./ArtifactAnalysis";

export function ResultView({ result, intelConfigured }: { result: InvestigationResult; intelConfigured?: boolean }) {
  const risk = result.risk_assessment;
  return (
    <div className="flex flex-col gap-5">
      <VerdictCard result={result} />
      <Notices result={result} intelConfigured={intelConfigured} />
      {result.analyst_report && <AnalystCard report={result.analyst_report} />}
      <div className="grid gap-5 2xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <FindingsList findings={risk?.findings ?? []} />
        {risk && <AttackPanel risk={risk} />}
      </div>
      <ArtifactAnalysis ingestion={result.ingestion} />
      <IndicatorExplorer result={result} />
      <PipelineTimeline metrics={result.execution_metrics} />
      <RuleAudit rules={risk?.applied_rules ?? []} />
    </div>
  );
}
