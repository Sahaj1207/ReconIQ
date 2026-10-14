import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { installFakeAuthApi } from "./test/fakeAuthApi";

const outages: [string, () => Promise<Response>][] = [
  ["the network is down", async () => Promise.reject(new TypeError("Failed to fetch"))],
  ["a proxy returns 502", async () => new Response("Bad gateway", { status: 502 })],
];

describe("App when the API is down", () => {
  it.each(outages)("says the API is unreachable when %s, then recovers on retry", async (_, outage) => {
    vi.stubGlobal("fetch", vi.fn(outage));
    render(<App />);

    expect(await screen.findByText("Can't reach the ReconIQ API")).toBeInTheDocument();
    expect(screen.queryByText(/Read-only access/)).not.toBeInTheDocument();

    installFakeAuthApi(); // the API comes back
    fireEvent.click(screen.getByRole("button", { name: "Retry now" }));
    expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });
});
