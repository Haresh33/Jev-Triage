/**
 * Microsoft Defender XDR advanced hunting through Microsoft Graph (runHuntingQuery, KQL).
 * App registration with the application permission ThreatHunting.Read.All; client-credentials token.
 * The older api.security.microsoft.com advanced hunting API is being retired, so it isn't used.
 */

import { describeFailure, http, isRecord, num, str, tokenCache } from "./http";
import { assertSafe, iso, quoted, regexLiteral } from "./safety";
import type { LogEvent, LogSource, Pivot } from "./types";

export type DefenderSettings = { tenantId: string; clientId: string; clientSecret: string; graphUrl: string; loginUrl: string; timeoutMs: number };

const hostFilter = (h: string) => `(DeviceName =~ ${quoted(h)} or DeviceName startswith ${quoted(`${h}.`)})`;
const PROC = `project Timestamp, DeviceName, Category = "process", AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, ActionType`;
const NET = `project Timestamp, DeviceName, Category = "network", AccountName = InitiatingProcessAccountName, FileName = InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, ActionType`;

/** The KQL for one pivot. Values are validated and quoted; times are ISO strings produced here. */
export function defenderQuery(p: Pivot, max: number): string {
  const when = `Timestamp between (datetime(${iso(p.start)}) .. datetime(${iso(p.end)}))`;
  const tail = `| sort by Timestamp desc | take ${max}`;
  switch (p.kind) {
    case "host_activity": { const h = assertSafe("host", p.value);
      return `union (DeviceProcessEvents | where ${when} and ${hostFilter(h)} | ${PROC}), (DeviceNetworkEvents | where ${when} and ${hostFilter(h)} | ${NET}) ${tail}`; }
    case "process_tree": { const h = assertSafe("host", p.value); const x = assertSafe("process", p.process ?? "");
      return `DeviceProcessEvents | where ${when} and ${hostFilter(h)} and (FileName =~ ${quoted(x)} or InitiatingProcessFileName =~ ${quoted(x)}) | ${PROC} ${tail}`; }
    case "user_activity": { const u = quoted(assertSafe("account", p.value));
      return `union (DeviceLogonEvents | where ${when} and AccountName =~ ${u} | project Timestamp, DeviceName, Category = "logon", AccountName, LogonType, RemoteIP, ActionType), (DeviceProcessEvents | where ${when} and AccountName =~ ${u} | ${PROC}) ${tail}`; }
    case "hash_prevalence": { const h = quoted(assertSafe("sha256", p.value));
      return `union (DeviceProcessEvents | where ${when} and SHA256 == ${h} | ${PROC}), (DeviceFileEvents | where ${when} and SHA256 == ${h} | project Timestamp, DeviceName, Category = "file", AccountName = InitiatingProcessAccountName, FileName, FolderPath, SHA256, ActionType) ${tail}`; }
    case "ip_prevalence":
      return `DeviceNetworkEvents | where ${when} and RemoteIP == ${quoted(assertSafe("ip", p.value))} | ${NET} ${tail}`;
    case "domain_prevalence":
      return `DeviceNetworkEvents | where ${when} and RemoteUrl matches regex @"(?i)(^|[/.@])${regexLiteral(assertSafe("domain", p.value))}($|[:/])" | ${NET} ${tail}`;
  }
}

export function defenderEvent(r: Record<string, unknown>): LogEvent {
  const cat = str(r.Category);
  const action = str(r.ActionType);
  return {
    time: str(r.Timestamp) ?? "", category: cat === "network" ? "network" : cat === "logon" ? "logon" : cat === "file" ? "file" : "process",
    host: str(r.DeviceName), user: str(r.AccountName), action, process: str(r.FileName), commandLine: str(r.ProcessCommandLine),
    parent: str(r.InitiatingProcessFileName), parentCommandLine: str(r.InitiatingProcessCommandLine), sha256: str(r.SHA256),
    dstIp: cat === "network" ? str(r.RemoteIP) : undefined, srcIp: cat === "logon" ? str(r.RemoteIP) : undefined, dstPort: num(r.RemotePort),
    domain: str(r.RemoteUrl)?.replace(/^[a-z]+:\/\//i, "").split(/[/:]/)[0], logonType: str(r.LogonType),
    outcome: action && /fail/i.test(action) ? "failure" : action && /success/i.test(action) ? "success" : undefined,
  };
}

export function defenderSource(s: DefenderSettings): LogSource {
  const token = tokenCache(async () => {
    const body = new URLSearchParams({ client_id: s.clientId, client_secret: s.clientSecret, scope: `${s.graphUrl}/.default`, grant_type: "client_credentials" });
    const r = await http(`${s.loginUrl}/${encodeURIComponent(s.tenantId)}/oauth2/v2.0/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body }, s.timeoutMs);
    if (r.status === 200 && isRecord(r.json) && typeof r.json.access_token === "string") return { token: r.json.access_token, expiresInSeconds: num(r.json.expires_in) ?? 3599 };
    return { error: describeFailure("Microsoft sign-in", r) };
  });
  return {
    provider: "defender",
    async search(p, max) {
      const started = performance.now(); let query = "";
      try { query = defenderQuery(p, max); } catch (e) { return { ok: false, events: [], truncated: false, query, error: String((e as Error).message), durationMs: 0 }; }
      const t = await token();
      if ("error" in t) return { ok: false, events: [], truncated: false, query, error: t.error, durationMs: Math.round(performance.now() - started) };
      const r = await http(`${s.graphUrl}/v1.0/security/runHuntingQuery`, { method: "POST", headers: { Authorization: `Bearer ${t.token}`, "Content-Type": "application/json; charset=utf-8" }, body: JSON.stringify({ Query: query, Timespan: `${iso(p.start)}/${iso(p.end)}` }) }, s.timeoutMs);
      const durationMs = Math.round(performance.now() - started);
      if (r.status !== 200 || !isRecord(r.json) || !Array.isArray(r.json.results)) return { ok: false, events: [], truncated: false, query, error: describeFailure("Defender", r), durationMs };
      const events = r.json.results.filter(isRecord).map(defenderEvent);
      return { ok: true, events, truncated: events.length >= max, query, durationMs };
    },
  };
}
