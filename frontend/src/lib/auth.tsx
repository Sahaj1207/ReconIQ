import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { getAuthConfig, getMe } from "./api";
import { UNAUTHORIZED_EVENT, loadSession, saveSession } from "./session";
import type { AuthConfig, Me, Role, Session } from "./types";

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

interface AuthState {
  config: AuthConfig | null;
  me: Me | null;
  session: Session | null;
  ready: boolean;
  signIn: (session: Session) => void;
  signOut: () => void;
  can: (role: Role) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [session, setSession] = useState<Session | null>(loadSession);
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);

  const refreshMe = useCallback(() => {
    getMe()
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setReady(true));
  }, []);

  useEffect(() => {
    getAuthConfig()
      .then(setConfig)
      .catch(() => setConfig(null))
      .finally(refreshMe);
  }, [refreshMe]);

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
      signIn,
      signOut,
      can: (role) => (me ? RANK[me.role] >= RANK[role] : false),
    }),
    [config, me, session, ready, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
