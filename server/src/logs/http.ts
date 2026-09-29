/** Shared HTTP plumbing for the log providers: timeouts, a size cap, no redirects, and cached OAuth tokens. */

const MAX_BYTES = 8_000_000;
const UA = "jev-triage/1.0";

export type HttpResult = { status: number; text: string; json: unknown };

export async function http(url: string, init: RequestInit, timeoutMs: number): Promise<HttpResult> {
  try {
    const res = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(timeoutMs), headers: { "User-Agent": UA, Accept: "application/json", ...(init.headers as Record<string, string> | undefined) } });
    const text = await res.text();
    if (text.length > MAX_BYTES) return { status: 0, text: "", json: null };
    let json: unknown = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    return { status: res.status, text, json };
  } catch (error) {
    return { status: 0, text: error instanceof Error ? error.message : String(error), json: null };
  }
}

export const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
export const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v : typeof v === "number" ? String(v) : Array.isArray(v) && v.length ? str(v[0]) : undefined);
export const num = (v: unknown): number | undefined => { const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN; return Number.isFinite(n) ? n : undefined; };

/** Human wording for a failed provider call. */
export function describeFailure(provider: string, r: HttpResult): string {
  if (r.status === 0) return `${provider} could not be reached or timed out.`;
  if (r.status === 401 || r.status === 403) return `${provider} refused the credentials (HTTP ${r.status}). Check the API key and its permissions.`;
  if (r.status === 429) return `${provider} rate limit reached.`;
  const detail = isRecord(r.json) ? JSON.stringify(r.json).slice(0, 200) : r.text.slice(0, 200);
  return `${provider} search failed (HTTP ${r.status})${detail ? `: ${detail}` : ""}.`;
}

/** Caches a bearer token until shortly before it expires; one refresh at a time. */
export function tokenCache(fetchToken: () => Promise<{ token: string; expiresInSeconds: number } | { error: string }>): () => Promise<{ token: string } | { error: string }> {
  let cached: { token: string; until: number } | null = null;
  let inflight: Promise<{ token: string } | { error: string }> | null = null;
  return async () => {
    if (cached && Date.now() < cached.until) return { token: cached.token };
    inflight ??= (async () => {
      const r = await fetchToken();
      if ("token" in r) cached = { token: r.token, until: Date.now() + Math.max(30, r.expiresInSeconds - 60) * 1000 };
      return "token" in r ? { token: r.token } : r;
    })().finally(() => { inflight = null; });
    return inflight;
  };
}
