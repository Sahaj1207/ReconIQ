import { useEffect, useState } from "react";
import { ArrowLeft, Loader2, Trash2 } from "lucide-react";
import { deleteInvestigation, getInvestigation } from "../lib/api";
import type { Capabilities, InvestigationResult } from "../lib/types";
import { ResultView } from "../components/ResultView";
import { useAuth } from "../lib/auth";

export function InvestigationPage({ id, caps }: { id: string; caps: Capabilities | null }) {
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { me, can } = useAuth();

  useEffect(() => {
    setResult(null);
    setError(null);
    getInvestigation(id).then(setResult).catch((e) => setError(e.message));
  }, [id]);

  const remove = async () => {
    if (!window.confirm("Delete this investigation permanently?")) return;
    try {
      await deleteInvestigation(id);
      window.location.hash = "#/history";
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="mx-auto flex max-w-[1200px] flex-col gap-4">
      <div className="flex items-center justify-between">
        <a href="#/history" className="btn-ghost -ml-2 text-xs">
          <ArrowLeft className="h-3.5 w-3.5" /> History
        </a>
        {result && (can("admin") || (can("analyst") && (me?.kind !== "user" || result.owner_id === me?.user?.id))) && (
          <button type="button" onClick={remove} className="btn-ghost text-xs hover:text-fail">
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </button>
        )}
      </div>
      {error && <div className="rounded-xl border border-fail/30 bg-fail/8 px-4 py-3 text-sm text-fail">{error}</div>}
      {!result && !error && (
        <div className="flex items-center gap-2 py-20 text-sm text-ink-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading investigation…
        </div>
      )}
      {result && <ResultView result={result} intelConfigured={caps ? caps.threat_intel.some((p) => p.enabled) : undefined} />}
    </div>
  );
}
