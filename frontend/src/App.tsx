import { useCallback, useEffect, useState } from "react";
import { AlertOctagon } from "lucide-react";
import { getHealth, investigate } from "./lib/api";
import { loadHistory, saveHistory } from "./lib/history";
import type { InvestigationResult } from "./lib/types";
import { Header, type ApiState } from "./components/Header";
import { InputPanel } from "./components/InputPanel";
import { HistoryList, type HistoryEntry } from "./components/HistoryList";
import { VerdictCard } from "./components/VerdictCard";
import { PipelineTimeline } from "./components/PipelineTimeline";
import { FindingsList } from "./components/FindingsList";
import { IndicatorExplorer } from "./components/IndicatorExplorer";
import { RuleAudit } from "./components/RuleAudit";
import { Notices } from "./components/Notices";
import { EmptyState } from "./components/EmptyState";

export default function App() {
  const [api, setApi] = useState<ApiState>({ kind: "checking" });
  const [text, setText] = useState("");
  const [refang, setRefang] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);

  useEffect(() => {
    let cancelled = false;
    const check = () =>
      getHealth()
        .then((health) => !cancelled && setApi({ kind: "online", health }))
        .catch(() => !cancelled && setApi({ kind: "offline" }));
    check();
    const id = setInterval(check, 30_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const run = useCallback(async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await investigate({ text, refang });
      setResult(res);
      setApi((prev) => (prev.kind === "offline" ? { kind: "checking" } : prev));
      setHistory((prev) => saveHistory([{ id: res.investigation_id, text, result: res }, ...prev]));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [text, refang]);

  const selectHistory = (entry: HistoryEntry) => {
    setText(entry.text);
    setResult(entry.result);
    setError(null);
  };

  const risk = result?.risk_assessment;

  return (
    <div className="min-h-screen">
      <Header api={api} />

      <main className="mx-auto grid max-w-[1500px] gap-5 px-4 py-5 sm:px-6 lg:grid-cols-[400px_minmax(0,1fr)] xl:grid-cols-[440px_minmax(0,1fr)]">
        <aside className="flex flex-col gap-5 lg:sticky lg:top-[76px] lg:self-start">
          <InputPanel
            text={text}
            refang={refang}
            loading={loading}
            onTextChange={setText}
            onRefangChange={setRefang}
            onSubmit={run}
          />
          <HistoryList
            entries={history}
            activeId={result?.investigation_id}
            onSelect={selectHistory}
            onClear={() => setHistory(saveHistory([]))}
          />
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

          {loading && !result && <PipelineTimeline loading />}

          {result ? (
            <div className={`flex flex-col gap-5 transition-opacity ${loading ? "opacity-60" : ""}`}>
              <VerdictCard result={result} />
              <Notices result={result} />
              <PipelineTimeline metrics={result.execution_metrics} />
              <div className="grid gap-5 2xl:grid-cols-2">
                <FindingsList findings={risk?.findings ?? []} />
                <RuleAudit rules={risk?.applied_rules ?? []} />
              </div>
              <IndicatorExplorer result={result} />
            </div>
          ) : (
            !loading && <EmptyState />
          )}
        </div>
      </main>

      <footer className="mx-auto max-w-[1500px] px-6 pb-6 text-[11px] text-ink-faint">
        ReconIQ · Deterministic-first investigation. AI never decides whether an artifact is malicious.
      </footer>
    </div>
  );
}
