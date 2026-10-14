import { vi } from "vitest";

interface FakeUser {
  id: string;
  email: string;
  name: string;
  role: "admin" | "analyst" | "viewer";
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/**
 * Installs an in-memory stand-in for the auth endpoints as global fetch. The first account becomes
 * admin, later ones analyst. `revoke(token)` makes a token start returning 401, and `holdNextMe()`
 * delays the next /auth/me so a test can resolve it after the session has changed.
 */
export function installFakeAuthApi() {
  const users: FakeUser[] = [];
  const tokens = new Map<string, FakeUser>();
  const revoked = new Set<string>();
  let held: { release: () => void } | null = null;
  let holdNext = false;

  const session = (user: FakeUser) => {
    const token = `token-${user.id}-${tokens.size}`;
    tokens.set(token, user);
    return { access_token: token, token_type: "bearer", expires_at: new Date(Date.now() + 3_600_000).toISOString(), user };
  };

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://localhost");
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const auth = new Headers(init.headers).get("Authorization")?.replace("Bearer ", "") ?? null;

    if (path === "/auth/config") {
      return json({ auth_required: true, signup_open: true, signup_role: "analyst", min_password_length: 8 });
    }
    if (path === "/auth/register" && init.method === "POST") {
      const body = JSON.parse(String(init.body));
      if (users.some((u) => u.email === body.email)) return json({ detail: "An account with this email already exists" }, 409);
      const user: FakeUser = { id: `u${users.length + 1}`, email: body.email, name: body.name, role: users.length ? "analyst" : "admin" };
      users.push(user);
      return json(session(user), 201);
    }
    if (path === "/auth/me") {
      if (holdNext) {
        holdNext = false;
        await new Promise<void>((resolve) => (held = { release: resolve }));
      }
      const user = auth && !revoked.has(auth) ? tokens.get(auth) : undefined;
      if (!user) return json({ detail: "Authentication required" }, 401);
      return json({ kind: "user", role: user.role, email: user.email, user });
    }
    return json({ detail: "Not found" }, 404);
  });

  vi.stubGlobal("fetch", fetchMock);
  return {
    fetchMock,
    users,
    revoke: (token: string) => revoked.add(token),
    holdNextMe: () => (holdNext = true),
    releaseHeldMe: () => held?.release(),
  };
}
