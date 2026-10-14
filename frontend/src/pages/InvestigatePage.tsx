import { useCallback, useState } from "react";
import { AlertOctagon } from "lucide-react";
import { startFileInvestigationJob, startInvestigationJob } from "../lib/api";
import type { Capabilities, InvestigationResult } from "../lib/types";
import { InputPanel, type InputMode } from "../components/InputPanel";
import { RecentList } from "../components/RecentList";
import { PipelineTimeline } from "../components/PipelineTimeline";
import { ResultView } from "../components/ResultView";
import { EmptyState } from "../components/EmptyState";
import { useAuth } from "../lib/auth";
import { JobSuperseded, useInvestigationJob } from "../lib/useInvestigationJob";

export function InvestigatePage({ caps }: { caps: Capabilities | null }) {
  const [mode, setMode] = useState<InputMode>("text");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [refang, setRefang] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const { job, running: loading, run: runJob } = useInvestigationJob();

  const run = useCallback(async () => {
    setError(null);
    try {
      const res = await runJob(() =>
        mode === "file" && file ? startFileInvestigationJob(file, refang) : startInvestigationJob({ text, refang }),
      );
      setResult(res);
      setRefreshKey((k) => k + 1);
    } catch (err) {
      if (!(err instanceof JobSuperseded)) setError(err instanceof Error ? err.message : String(err));
    }
  }, [mode, file, text, refang, runJob]);

  const intelConfigured = caps ? caps.threat_intel.some((p) => p.enabled) : undefined;
  const { can } = useAuth();

  if (!can("analyst")) {
    return (
      <div className="mx-auto max-w-xl py-16 text-center">
        <h2 className="text-lg font-semibold">Read-only access</h2>
        <p className="mt-2 text-sm text-ink-muted">
          Your account has the viewer role, so you can browse investigations and reports but not run new ones. Ask an
          administrator for analyst access.
        </p>
        <a href="#/history" className="btn-primary mt-5 inline-flex">Browse history</a>
      </div>
    );
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[400px_minmax(0,1fr)] xl:grid-cols-[440px_minmax(0,1fr)]">
      <aside className="flex flex-col gap-5 lg:sticky lg:top-[76px] lg:self-start">
        <InputPanel
          mode={mode}
          text={text}
          file={file}
          refang={refang}
          loading={loading}
          maxUploadMb={caps?.ingestion.max_upload_mb ?? 15}
          onModeChange={setMode}
          onTextChange={setText}
          onFileChange={setFile}
          onRefangChange={setRefang}
          onSubmit={run}
        />
        <RecentList refreshKey={refreshKey} activeId={result?.investigation_id} />
      </aside>

      <div className="flex min-w-0 flex-col gap-5">
        {error && (
          <div role="alert" className="flex items-start gap-3 rounded-xl border border-fail/30 bg-fail/8 px-4 py-3 text-sm text-fail">
            <AlertOctagon className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <div className="font-medium">Investigation failed</div>
              <div className="text-fail/80">{error}</div>
            </div>
          </div>
        )}
        {loading && <PipelineTimeline metrics={job?.stages} progress={job?.progress} loading />}
        {result ? (
          <div className={`transition-opacity ${loading ? "opacity-60" : ""}`}>
            <ResultView result={result} intelConfigured={intelConfigured} />
          </div>
        ) : (
          !loading && <EmptyState />
        )}
      </div>
    </div>
  );
}
