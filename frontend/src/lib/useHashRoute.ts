import { useEffect, useState } from "react";

export type Route =
  | { page: "investigate" }
  | { page: "history" }
  | { page: "system" }
  | { page: "investigation"; id: string };

function parse(hash: string): Route {
  const path = hash.replace(/^#/, "");
  const match = path.match(/^\/investigations\/([\w-]+)$/);
  if (match) return { page: "investigation", id: match[1] };
  if (path === "/history") return { page: "history" };
  if (path === "/system") return { page: "system" };
  return { page: "investigate" };
}

/** Minimal hash router: no dependency, works on any static host. */
export function useHashRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parse(window.location.hash));
  useEffect(() => {
    const onChange = () => {
      setRoute(parse(window.location.hash));
      window.scrollTo({ top: 0 });
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
