/**
 * Google Security Operations (Chronicle) UDM search through the Chronicle API:
 *   GET https://{location}-chronicle.googleapis.com/v1/projects/{project}/locations/{location}/instances/{instance}:udmSearch
 * Auth: a Google service account (JSON key) with the chronicle.events.udmSearch permission, exchanged for an
 * OAuth token (scope cloud-platform) with a signed JWT. The legacy Backstory API is deprecated and isn't used.
 */

import { describeFailure, http, isRecord, num, str, tokenCache } from "./http";
import { assertSafe, iso, quoted, regexLiteral } from "./safety";
import type { LogEvent, LogSource, Pivot } from "./types";

export type ServiceAccount = { client_email: string; private_key: string; token_uri?: string };
export type SecOpsSettings = { baseUrl: string; project: string; location: string; instance: string; account: ServiceAccount; timeoutMs: number };

const b64url = (data: ArrayBuffer | Uint8Array | string) => Buffer.from(typeof data === "string" ? data : data instanceof Uint8Array ? data : new Uint8Array(data)).toString("base64url");

/** A signed service-account JWT for the OAuth token exchange (RS256). */
export async function serviceAccountJwt(account: ServiceAccount, scope: string, now = Math.floor(Date.now() / 1000)): Promise<string> {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = b64url(JSON.stringify({ iss: account.client_email, scope, aud: account.token_uri ?? "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const pem = account.private_key.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Buffer.from(pem, "base64"), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${header}.${claims}`));
  return `${header}.${claims}.${b64url(sig)}`;
}

const hostRe = (h: string) => `/^${regexLiteral(h)}(\\..*)?$/ nocase`;
const hostClause = (h: string) => `(principal.hostname = ${hostRe(h)} OR principal.asset.hostname = ${hostRe(h)})`;

/** The UDM search query for one pivot. Values are validated; regexes are built only from escaped, validated values. */
export function secopsQuery(p: Pivot): string {
  switch (p.kind) {
    case "host_activity": return `${hostClause(assertSafe("host", p.value))} AND (metadata.event_type = "PROCESS_LAUNCH" OR metadata.event_type = "NETWORK_CONNECTION" OR metadata.event_type = "NETWORK_DNS")`;
    case "process_tree": { const x = regexLiteral(assertSafe("process", p.process ?? ""));
      return `${hostClause(assertSafe("host", p.value))} AND metadata.event_type = "PROCESS_LAUNCH" AND (target.process.file.full_path = /(^|[\\\\\\/])${x}$/ nocase OR principal.process.file.full_path = /(^|[\\\\\\/])${x}$/ nocase)`; }
    case "user_activity": { const u = quoted(assertSafe("account", p.value)); return `(principal.user.userid = ${u} nocase OR target.user.userid = ${u} nocase)`; }
    case "hash_prevalence": { const h = quoted(assertSafe("sha256", p.value)); return `(target.process.file.sha256 = ${h} nocase OR target.file.sha256 = ${h} nocase)`; }
    case "ip_prevalence": { const ip = quoted(assertSafe("ip", p.value)); return `(target.ip = ${ip} OR principal.ip = ${ip})`; }
    case "domain_prevalence": { const d = quoted(assertSafe("domain", p.value)); return `(network.dns.questions.name = ${d} nocase OR target.hostname = ${d} nocase)`; }
  }
}

export function secopsEvent(e: Record<string, unknown>): LogEvent {
  const u = isRecord(e.udm) ? e.udm : e;
  const g = (path: string): unknown => path.split(".").reduce<unknown>((v, k) => (isRecord(v) ? v[k] : Array.isArray(v) && isRecord(v[0]) ? (v[0] as Record<string, unknown>)[k] : undefined), u);
  const type = str(g("metadata.eventType")) ?? "";
  const category: LogEvent["category"] = type === "PROCESS_LAUNCH" ? "process" : type === "NETWORK_DNS" ? "dns" : type.startsWith("NETWORK") ? "network" : type.startsWith("USER_") ? "logon" : type.startsWith("FILE_") ? "file" : "other";
  const base = (p: unknown) => str(p)?.split(/[\\/]/).pop();
  return {
    time: str(g("metadata.eventTimestamp")) ?? "", category, action: type || undefined,
    host: str(g("principal.hostname")) ?? str(g("principal.asset.hostname")), user: str(g("principal.user.userid")) ?? str(g("target.user.userid")),
    process: base(g("target.process.file.fullPath")), commandLine: str(g("target.process.commandLine")), parent: base(g("principal.process.file.fullPath")), parentCommandLine: str(g("principal.process.commandLine")),
    sha256: str(g("target.process.file.sha256")) ?? str(g("target.file.sha256")), srcIp: str(g("principal.ip")), dstIp: str(g("target.ip")), dstPort: num(g("target.port")),
    domain: str(g("network.dns.questions.name")) ?? (category === "network" ? str(g("target.hostname")) : undefined), outcome: str(g("securityResult.action")),
  };
}

export function secopsSource(s: SecOpsSettings): LogSource {
  const token = tokenCache(async () => {
    let assertion: string;
    try { assertion = await serviceAccountJwt(s.account, "https://www.googleapis.com/auth/cloud-platform"); } catch { return { error: "Google SecOps: the service account key could not be read." }; }
    const r = await http(s.account.token_uri ?? "https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }) }, s.timeoutMs);
    if (r.status === 200 && isRecord(r.json) && typeof r.json.access_token === "string") return { token: r.json.access_token, expiresInSeconds: num(r.json.expires_in) ?? 3599 };
    return { error: describeFailure("Google sign-in", r) };
  });
  const path = `/v1/projects/${encodeURIComponent(s.project)}/locations/${encodeURIComponent(s.location)}/instances/${encodeURIComponent(s.instance)}:udmSearch`;
  return {
    provider: "secops",
    async search(p, max) {
      const started = performance.now(); let query = "";
      try { query = secopsQuery(p); } catch (e) { return { ok: false, events: [], truncated: false, query, error: String((e as Error).message), durationMs: 0 }; }
      const t = await token();
      if ("error" in t) return { ok: false, events: [], truncated: false, query, error: t.error, durationMs: Math.round(performance.now() - started) };
      const params = new URLSearchParams({ query, "timeRange.startTime": iso(p.start), "timeRange.endTime": iso(p.end), limit: String(max) });
      const r = await http(`${s.baseUrl}${path}?${params}`, { method: "GET", headers: { Authorization: `Bearer ${t.token}` } }, s.timeoutMs);
      const durationMs = Math.round(performance.now() - started);
      if (r.status !== 200 || !isRecord(r.json)) return { ok: false, events: [], truncated: false, query, error: describeFailure("Google SecOps", r), durationMs };
      const events = (Array.isArray(r.json.events) ? r.json.events : []).filter(isRecord).map(secopsEvent);
      return { ok: true, events, truncated: r.json.moreDataAvailable === true || events.length >= max, query, durationMs };
    },
  };
}
