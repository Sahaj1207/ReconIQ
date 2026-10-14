import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AuthProvider, useAuth } from "./auth";
import { getMe } from "./api";
import { loadSession } from "./session";
import { AuthPage } from "../pages/AuthPage";
import { installFakeAuthApi } from "../test/fakeAuthApi";

function Shell() {
  const { ready, me, signOut } = useAuth();
  if (!ready) return <p>loading</p>;
  if (!me) return <AuthPage />;
  return (
    <div>
      <p data-testid="who">
        {me.email} ({me.role})
      </p>
      <button onClick={signOut}>Sign out</button>
    </div>
  );
}

async function signUp(name: string, email: string) {
  fireEvent.click(await screen.findByRole("button", { name: "Create an account" }));
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: name } });
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "long-enough-password" } });
  fireEvent.click(screen.getByRole("button", { name: "Create account" }));
}

describe("AuthProvider sessions", () => {
  it("signs up an admin, signs out, then signs up a second user without hanging", async () => {
    installFakeAuthApi();
    render(<AuthProvider><Shell /></AuthProvider>);

    await signUp("Admin", "admin@example.com");
    expect(await screen.findByTestId("who")).toHaveTextContent("admin@example.com (admin)");

    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await signUp("Second", "second@example.com");
    expect(await screen.findByTestId("who")).toHaveTextContent("second@example.com (analyst)");
    expect(loadSession()?.user.email).toBe("second@example.com");
  });

  it("ignores a 401 for an earlier session's token", async () => {
    const api = installFakeAuthApi();
    render(<AuthProvider><Shell /></AuthProvider>);
    await signUp("Admin", "admin@example.com");
    await screen.findByTestId("who");
    const firstToken = loadSession()!.access_token;

    // A request sent with the first token is still in flight when the user switches accounts...
    api.holdNextMe();
    const stale = getMe().catch(() => undefined);
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await signUp("Second", "second@example.com");
    await waitFor(() => expect(screen.getByTestId("who")).toHaveTextContent("second@example.com"));

    // ...and comes back 401 only after the second session has started. It must not sign them out.
    api.revoke(firstToken);
    await act(async () => {
      api.releaseHeldMe();
      await stale;
    });
    expect(screen.getByTestId("who")).toHaveTextContent("second@example.com");
    expect(loadSession()?.user.email).toBe("second@example.com");
  });

  it("ends the session when the current token is rejected", async () => {
    const api = installFakeAuthApi();
    render(<AuthProvider><Shell /></AuthProvider>);
    await signUp("Admin", "admin@example.com");
    await screen.findByTestId("who");

    api.revoke(loadSession()!.access_token);
    await act(async () => {
      await getMe().catch(() => undefined);
    });
    expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument();
    expect(loadSession()).toBeNull();
  });
});
