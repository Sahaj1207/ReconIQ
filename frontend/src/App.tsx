import { useCallback, useEffect, useState } from "react";
import { Loader2, WifiOff } from "lucide-react";
import { getCapabilities, getHealth } from "./lib/api";
import { AuthProvider, useAuth } from "./lib/auth";
import type { Capabilities } from "./lib/types";
import { useHashRoute } from "./lib/useHashRoute";
import { Header, type ApiState } from "./components/Header";
import { InvestigatePage } from "./pages/InvestigatePage";
import { HistoryPage } from "./pages/HistoryPage";
import { InvestigationPage } from "./pages/InvestigationPage";
import { SystemPage } from "./pages/SystemPage";
import { AdminPage } from "./pages/AdminPage";
import { AuthPage } from "./pages/AuthPage";

export default function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  );
}

function Shell() {
  const route = useHashRoute();
  const { ready, me, config, can, unreachable, reload } = useAuth();
  const [api, setApi] = useState<ApiState>({ kind: "checking" });
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [capsError, setCapsError] = useState<string | null>(null);

  const loadCaps = useCallback(() => {
    getCapabilities()
      .then((c) => {
        setCaps(c);
        setCapsError(null);
      })
      .catch((e) => setCapsError(e.message));
  }, []);

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

  useEffect(() => {
    if (me) loadCaps();
  }, [me, loadCaps]);

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center gap-2 text-sm text-ink-muted">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading ReconIQ…
      </div>
    );
  }
  if (unreachable) return <ApiUnreachable onRetry={reload} />;
  if (!me && (config?.auth_required ?? false)) return <AuthPage />;

  return (
    <div className="min-h-screen">
      <Header api={api} route={route} />
      <main className="mx-auto max-w-[1500px] px-4 py-5 sm:px-6">
        {route.page === "investigate" && <InvestigatePage caps={caps} />}
        {route.page === "history" && <HistoryPage />}
        {route.page === "investigation" && <InvestigationPage id={route.id} caps={caps} />}
        {route.page === "system" && <SystemPage caps={caps} error={capsError} onKeySaved={loadCaps} />}
        {route.page === "admin" &&
          (can("admin") ? <AdminPage tab={route.tab} /> : <p className="text-sm text-ink-muted">Administrators only.</p>)}
      </main>
      <footer className="mx-auto max-w-[1500px] px-6 pb-6 text-[11px] text-ink-faint">
        ReconIQ · Deterministic investigation: every verdict comes from fixed, auditable rules.
      </footer>
    </div>
  );
}

const RETRY_MS = 10_000;

/** Shown when the API can't be reached at all; retries automatically until it is back. */
function ApiUnreachable({ onRetry }: { onRetry: () => void }) {
  useEffect(() => {
    const id = setInterval(onRetry, RETRY_MS);
    return () => clearInterval(id);
  }, [onRetry]);

  return (
    <div role="alert" className="flex min-h-screen items-center justify-center px-4">
      <div className="card max-w-md p-6 text-center">
        <WifiOff className="mx-auto h-8 w-8 text-fail" />
        <h1 className="mt-3 text-lg font-semibold">Can't reach the ReconIQ API</h1>
        <p className="mt-2 text-sm text-ink-muted">
          The service may be restarting or your connection may be down. This page retries automatically every{" "}
          {RETRY_MS / 1000} seconds.
        </p>
        <button type="button" className="btn-primary mt-5 inline-flex" onClick={onRetry}>
          Retry now
        </button>
      </div>
    </div>
  );
}
