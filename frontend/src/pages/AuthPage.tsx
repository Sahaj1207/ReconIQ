import { useState } from "react";
import { Loader2, ShieldCheck } from "lucide-react";
import { login, register } from "../lib/api";
import { useAuth } from "../lib/auth";

export function AuthPage() {
  const { config, signIn } = useAuth();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const minLength = config?.min_password_length ?? 8;
  const signupOpen = config?.signup_open ?? false;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      signIn(mode === "login" ? await login(email, password) : await register(email, password, name));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const input =
    "mt-1 w-full rounded-lg border border-line bg-canvas/60 px-3 py-2 text-[14px] text-ink placeholder:text-ink-faint focus:border-accent/60 focus:outline-none";

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="grid h-12 w-12 place-items-center rounded-xl bg-accent/15 ring-1 ring-accent/30">
            <ShieldCheck className="h-6 w-6 text-accent" />
          </div>
          <h1 className="mt-3 text-xl font-semibold tracking-tight">
            Recon<span className="text-accent">IQ</span>
          </h1>
          <p className="text-[13px] text-ink-faint">Evidence. Intelligence. Trust.</p>
        </div>

        <form onSubmit={submit} className="card space-y-4 p-6">
          <h2 className="text-[15px] font-semibold">{mode === "login" ? "Sign in" : "Create your account"}</h2>
          {mode === "register" && (
            <label className="block text-[12px] text-ink-muted">
              Name
              <input className={input} value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" maxLength={120} />
            </label>
          )}
          <label className="block text-[12px] text-ink-muted">
            Email
            <input className={input} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
          </label>
          <label className="block text-[12px] text-ink-muted">
            Password
            <input
              className={input}
              type="password"
              required
              minLength={mode === "register" ? minLength : 1}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={mode === "login" ? "current-password" : "new-password"}
            />
            {mode === "register" && <span className="mt-1 block text-[11px] text-ink-faint">At least {minLength} characters</span>}
          </label>
          {error && <p className="rounded-md border border-fail/30 bg-fail/8 px-3 py-2 text-[12.5px] text-fail" role="alert">{error}</p>}
          <button type="submit" className="btn-primary w-full" disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {mode === "login" ? "Sign in" : "Create account"}
          </button>
          {signupOpen && (
            <p className="text-center text-[12.5px] text-ink-muted">
              {mode === "login" ? "New to ReconIQ? " : "Already have an account? "}
              <button
                type="button"
                className="font-medium text-accent hover:underline"
                onClick={() => {
                  setMode(mode === "login" ? "register" : "login");
                  setError(null);
                }}
              >
                {mode === "login" ? "Create an account" : "Sign in"}
              </button>
            </p>
          )}
          {!signupOpen && mode === "login" && (
            <p className="text-center text-[12px] text-ink-faint">Accounts are created by an administrator.</p>
          )}
        </form>
      </div>
    </div>
  );
}
