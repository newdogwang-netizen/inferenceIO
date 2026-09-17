// Thin fetch wrapper. In dev the console relies on IOREC_AUTH_MODE=dev (no token);
// in token/OIDC mode the bearer token is kept in localStorage under iorec.token.
export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function token(): string | null {
  return localStorage.getItem("iorec.token");
}

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined) };
  const t = token();
  if (t) headers["Authorization"] = `Bearer ${t}`;
  if (init.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let code = "http_" + res.status;
    let message = res.statusText;
    try {
      const j = await res.json();
      code = j.error?.code ?? code;
      message = j.error?.message ?? message;
    } catch {}
    throw new ApiError(res.status, code, message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const enc = (s: string) => encodeURIComponent(s);

export function fmtTime(s?: string | null): string {
  if (!s) return "–";
  const d = new Date(s);
  return d.toLocaleString(undefined, { hour12: false });
}

export function fmtDur(a?: string | null, b?: string | null): string {
  if (!a || !b) return "–";
  const ms = new Date(b).getTime() - new Date(a).getTime();
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function short(s?: string | null, n = 28): string {
  if (!s) return "";
  return s.length > n ? "…" + s.slice(-n) : s;
}
