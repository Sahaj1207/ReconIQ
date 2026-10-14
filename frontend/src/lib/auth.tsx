import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { ApiError, getAuthConfig, getMe } from "./api";
import { UNAUTHORIZED_EVENT, loadSession, saveSession } from "./session";
import type { AuthConfig, Me, Role, Session } from "./types";

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

interface AuthState {
  config: AuthConfig | null;
  me: Me | null;
  session: Session | null;
  ready: boolean;
  /** True when the API could not be reached at all (network error), as opposed to an error response. */
  unreachable: boolean;
  reload: () => void;
  signIn: (session: Session) => void;
  signOut: () => void;
  can: (role: Role) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

/** Network failure or a 5xx from the API or its proxy: the service is down, not answering "no". */
const isOutage = (err: unknown) => err instanceof ApiError && (err.status === undefined || err.status >= 500);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [session, setSession] = useState<Session | null>(loadSession);
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);
  const [unreachable, setUnreachable] = useState(false);

  const refreshMe = useCallback(() => {
    getMe()
      .then((m) => {
        setMe(m);
        setUnreachable(false);
      })
      .catch((err) => {
        setMe(null);
        if (isOutage(err)) setUnreachable(true);
      })
      .finally(() => setReady(true));
  }, []);

  const load = useCallback(() => {
    getAuthConfig()
      .then((c) => {
        setConfig(c);
        setUnreachable(false);
        refreshMe();
      })
      .catch((err) => {
        setConfig(null);
        if (isOutage(err)) {
          // Don't guess at auth settings or roles while the API is down; report the outage instead.
          setUnreachable(true);
          setReady(true);
        } else {
          refreshMe();
        }
      });
  }, [refreshMe]);

  useEffect(() => load(), [load]);

  const signOut = useCallback(() => {
    saveSession(null);
    setSession(null);
    setMe(null);
    refreshMe();
  }, [refreshMe]);

  useEffect(() => {
    const onUnauthorized = (e: Event) => {
      const rejected = (e as CustomEvent<string>).detail;
      if (rejected && loadSession()?.access_token === rejected) signOut();
    };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [signOut]);

  const signIn = useCallback(
    (s: Session) => {
      saveSession(s);
      setSession(s);
      refreshMe();
    },
    [refreshMe],
  );

  const value = useMemo<AuthState>(
    () => ({
      config,
      me,
      session,
      ready,
      unreachable,
      reload: load,
      signIn,
      signOut,
      can: (role) => (me ? RANK[me.role] >= RANK[role] : false),
    }),
    [config, me, session, ready, unreachable, load, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
