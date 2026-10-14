import { useCallback, useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, KeyRound, Loader2, ScrollText, Trash2, UserPlus, Users } from "lucide-react";
import { createUser, deleteUser, listAudit, listUsers, updateUser } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { AuditEvent, Role, User } from "../lib/types";
import { formatRelativeTime } from "../lib/format";

const ROLES: Role[] = ["viewer", "analyst", "admin"];
const field =
  "rounded-lg border border-line bg-canvas/60 px-2.5 py-1.5 text-[13px] text-ink placeholder:text-ink-faint focus:border-accent/60 focus:outline-none";

export function AdminPage({ tab }: { tab: "users" | "audit" }) {
  return (
    <div className="mx-auto flex max-w-[1200px] flex-col gap-4">
      <div className="flex gap-1">
        {([
          { id: "users", label: "Users", icon: Users, href: "#/admin" },
          { id: "audit", label: "Audit log", icon: ScrollText, href: "#/admin/audit" },
        ] as const).map(({ id, label, icon: Icon, href }) => (
          <a
            key={id}
            href={href}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[13px] font-medium ${tab === id ? "bg-surface-2 text-ink" : "text-ink-muted hover:text-ink"}`}
          >
            <Icon className="h-4 w-4" /> {label}
          </a>
        ))}
      </div>
      {tab === "users" ? <UsersPanel /> : <AuditPanel />}
    </div>
  );
}

function UsersPanel() {
  const { me } = useAuth();
  const [users, setUsers] = useState<User[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ email: "", name: "", password: "", role: "analyst" as Role });
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    listUsers().then((r) => setUsers(r.items)).catch((e) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    await act(async () => {
      await createUser(form);
      setForm({ email: "", name: "", password: "", role: "analyst" });
    });
    setCreating(false);
  };

  return (
    <>
      <section className="card">
        <div className="card-header">
          <h2 className="card-title"><UserPlus className="h-4 w-4 text-accent" /> Add a user</h2>
        </div>
        <form onSubmit={create} className="flex flex-wrap items-end gap-2 p-4">
          <input className={`${field} min-w-[200px] flex-1`} type="email" required placeholder="email@company.com"
            value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} aria-label="Email" />
          <input className={`${field} w-40`} placeholder="Name" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })} aria-label="Name" />
          <input className={`${field} w-48`} type="password" required minLength={8} placeholder="Temporary password"
            value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} aria-label="Temporary password" />
          <select className={field} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })} aria-label="Role">
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <button type="submit" className="btn-primary py-1.5" disabled={creating}>
            {creating && <Loader2 className="h-4 w-4 animate-spin" />} Add user
          </button>
        </form>
      </section>

      {error && <div className="rounded-lg border border-fail/30 bg-fail/8 px-4 py-2.5 text-[13px] text-fail" role="alert">{error}</div>}

      <section className="card">
        <div className="card-header">
          <h2 className="card-title"><Users className="h-4 w-4 text-accent" /> Users
            {users && <span className="rounded-full bg-surface-2 px-2 text-[11px] font-medium text-ink-muted">{users.length}</span>}
          </h2>
        </div>
        {!users ? (
          <div className="flex items-center gap-2 px-5 py-8 text-sm text-ink-muted"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-[13px]">
              <thead className="text-[11px] uppercase tracking-wider text-ink-faint">
                <tr className="border-b border-line">
                  <th className="px-5 py-2.5 font-medium">User</th>
                  <th className="px-3 py-2.5 font-medium">Role</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Last sign-in</th>
                  <th className="px-5 py-2.5 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {users.map((u) => {
                  const self = u.id === me?.user?.id;
                  return (
                    <tr key={u.id}>
                      <td className="px-5 py-2.5">
                        <div className="text-ink">{u.name || u.email}{self && <span className="ml-2 chip bg-accent/15 text-accent">you</span>}</div>
                        {u.name && <div className="text-[11.5px] text-ink-faint">{u.email}</div>}
                      </td>
                      <td className="px-3 py-2.5">
                        <select className={field} value={u.role} aria-label={`Role for ${u.email}`}
                          onChange={(e) => act(() => updateUser(u.id, { role: e.target.value as Role }))}>
                          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                        </select>
                      </td>
                      <td className="px-3 py-2.5">
                        <button type="button" disabled={self}
                          onClick={() => act(() => updateUser(u.id, { is_active: !u.is_active }))}
                          className={`chip ${u.is_active ? "bg-ok/10 text-ok" : "bg-surface-2 text-ink-faint"} disabled:cursor-default`}
                          title={self ? undefined : u.is_active ? "Click to deactivate" : "Click to reactivate"}>
                          {u.is_active ? "active" : "deactivated"}
                        </button>
                      </td>
                      <td className="px-3 py-2.5 text-ink-faint">{u.last_login_at ? formatRelativeTime(u.last_login_at) : "never"}</td>
                      <td className="px-5 py-2.5">
                        <div className="flex justify-end gap-1">
                          <button type="button" className="btn-ghost px-2 py-1 text-xs" title="Reset password"
                            onClick={() => {
                              const pw = window.prompt(`New password for ${u.email} (min 8 characters)`);
                              if (pw) act(() => updateUser(u.id, { password: pw }));
                            }}>
                            <KeyRound className="h-3.5 w-3.5" /> Reset
                          </button>
                          {!self && (
                            <button type="button" className="btn-ghost px-2 py-1 text-xs hover:text-fail" title="Delete user"
                              onClick={() => window.confirm(`Delete ${u.email}? Their investigations are kept.`) && act(() => deleteUser(u.id))}>
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

const PAGE = 50;

function AuditPanel() {
  const [data, setData] = useState<{ total: number; items: AuditEvent[] } | null>(null);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listAudit({ limit: PAGE, offset }).then(setData).catch((e) => setError(e.message));
  }, [offset]);

  return (
    <section className="card">
      <div className="card-header">
        <h2 className="card-title"><ScrollText className="h-4 w-4 text-accent" /> Audit log</h2>
      </div>
      {error && <p className="px-5 py-3 text-[13px] text-fail">{error}</p>}
      {!data ? (
        <div className="flex items-center gap-2 px-5 py-8 text-sm text-ink-muted"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-[13px]">
              <thead className="text-[11px] uppercase tracking-wider text-ink-faint">
                <tr className="border-b border-line">
                  <th className="px-5 py-2.5 font-medium">When</th>
                  <th className="px-3 py-2.5 font-medium">Actor</th>
                  <th className="px-3 py-2.5 font-medium">Action</th>
                  <th className="px-3 py-2.5 font-medium">Target</th>
                  <th className="px-5 py-2.5 font-medium">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.items.map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap px-5 py-2 text-ink-faint" title={new Date(e.created_at).toLocaleString()}>{formatRelativeTime(e.created_at)}</td>
                    <td className="px-3 py-2 text-ink-muted">{e.actor_email ?? (e.detail?.email as string) ?? "—"}</td>
                    <td className="px-3 py-2"><span className={`chip font-mono ${e.action.includes("failed") || e.action.includes("deleted") ? "bg-sev-medium/12 text-sev-medium" : "bg-surface-2 text-ink-muted"}`}>{e.action}</span></td>
                    <td className="px-3 py-2 font-mono text-[11.5px] text-ink-faint">
                      {e.target_type === "investigation" && e.target_id ? (
                        <a className="hover:text-accent" href={`#/investigations/${e.target_id}`}>{e.target_id.slice(0, 8)}</a>
                      ) : e.target_id ? `${e.target_type}:${e.target_id.slice(0, 8)}` : "—"}
                    </td>
                    <td className="px-5 py-2 font-mono text-[11.5px] text-ink-faint">{e.ip ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between border-t border-line px-5 py-2.5 text-xs text-ink-faint">
            <span>{data.total ? `${offset + 1}–${Math.min(offset + PAGE, data.total)} of ${data.total}` : "No events"}</span>
            <div className="flex gap-1">
              <button type="button" className="btn-ghost px-2 py-1" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
                <ChevronLeft className="h-3.5 w-3.5" /> Prev
              </button>
              <button type="button" className="btn-ghost px-2 py-1" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>
                Next <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
