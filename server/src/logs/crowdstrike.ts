/**
 * CrowdStrike Falcon: event search over Falcon telemetry with Next-Gen SIEM query jobs (CQL):
 *   POST /humio/api/v1/repositories/{repo}/queryjobs      start (needs the NGSIEM read and write scopes)
 *   GET  /humio/api/v1/repositories/{repo}/queryjobs/{id} poll until done
 *   DELETE the job afterwards.
 * OAuth2 client credentials. Host names come from aid_master_main.csv, since not every event carries ComputerName.
 */

import { describeFailure, http, isRecord, num, str, tokenCache } from "./http";
import { assertSafe, quoted, regexLiteral } from "./safety";
import type { LogEvent, LogSource, Pivot } from "./types";

export type CrowdStrikeSettings = { baseUrl: string; clientId: string; clientSecret: string; memberCid?: string; repository: string; timeoutMs: number; pollMs?: number };

const HOSTNAME = `| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)`;
const hostRe = (h: string) => `/^${regexLiteral(h)}(\\..*)?$/i`;
const exact = (v: string) => `/^${regexLiteral(v)}$/i`;
const TABLE = `table([@timestamp, #event_simpleName, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData, RemoteAddressIP4, RemotePort, LocalAddressIP4, DomainName, LogonType], limit=`;

/** The CQL for one pivot. Values are validated; regexes are built only from escaped, validated values. */
export function crowdstrikeQuery(p: Pivot, max: number): string {
  const end = `| tail(${max}) | ${TABLE}${max})`;
  switch (p.kind) {
    case "host_activity": return `#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4|DnsRequest)$/ ${HOSTNAME} | ComputerName=${hostRe(assertSafe("host", p.value))} ${end}`;
    case "process_tree": { const x = exact(assertSafe("process", p.process ?? "")); return `#event_simpleName=ProcessRollup2 (FileName=${x} OR ParentBaseFileName=${x}) ${HOSTNAME} | ComputerName=${hostRe(assertSafe("host", p.value))} ${end}`; }
    case "user_activity": return `#event_simpleName=/^(UserLogon|UserLogonFailed2|ProcessRollup2)$/ UserName=${exact(assertSafe("account", p.value))} ${HOSTNAME} ${end}`;
    case "hash_prevalence": return `#event_simpleName=ProcessRollup2 SHA256HashData=${exact(assertSafe("sha256", p.value))} ${HOSTNAME} ${end}`;
    case "ip_prevalence": return `#event_simpleName=/^NetworkConnectIP[46]$/ RemoteAddressIP4=${quoted(assertSafe("ip", p.value))} ${HOSTNAME} ${end}`;
    case "domain_prevalence": return `#event_simpleName=DnsRequest DomainName=/(^|\\.)${regexLiteral(assertSafe("domain", p.value))}$/i ${HOSTNAME} ${end}`;
  }
}

export function crowdstrikeEvent(e: Record<string, unknown>): LogEvent {
  const name = str(e["#event_simpleName"]) ?? "";
  const category: LogEvent["category"] = name === "ProcessRollup2" ? "process" : name === "DnsRequest" ? "dns" : name.startsWith("NetworkConnect") ? "network" : name.startsWith("UserLogon") ? "logon" : "other";
  const ts = num(e["@timestamp"]);
  return {
    time: ts ? new Date(ts).toISOString() : str(e["@timestamp"]) ?? "", category, action: name || undefined,
    host: str(e.ComputerName), user: str(e.UserName), process: str(e.FileName), commandLine: str(e.CommandLine), parent: str(e.ParentBaseFileName),
    sha256: str(e.SHA256HashData), dstIp: category === "network" ? str(e.RemoteAddressIP4) : undefined, srcIp: category === "logon" ? str(e.RemoteAddressIP4) : str(e.LocalAddressIP4),
    dstPort: num(e.RemotePort), domain: str(e.DomainName), logonType: str(e.LogonType), outcome: name === "UserLogonFailed2" ? "failure" : name === "UserLogon" ? "success" : undefined,
  };
}

export function crowdstrikeSource(s: CrowdStrikeSettings): LogSource {
  const token = tokenCache(async () => {
    const form = new URLSearchParams({ client_id: s.clientId, client_secret: s.clientSecret, ...(s.memberCid ? { member_cid: s.memberCid } : {}) });
    const r = await http(`${s.baseUrl}/oauth2/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form }, s.timeoutMs);
    if ((r.status === 200 || r.status === 201) && isRecord(r.json) && typeof r.json.access_token === "string") return { token: r.json.access_token, expiresInSeconds: num(r.json.expires_in) ?? 1799 };
    return { error: describeFailure("CrowdStrike sign-in", r) };
  });
  const jobs = `${s.baseUrl}/humio/api/v1/repositories/${encodeURIComponent(s.repository)}/queryjobs`;
  return {
    provider: "crowdstrike",
    async search(p, max) {
      const started = performance.now(); let query = "";
      const took = () => Math.round(performance.now() - started);
      try { query = crowdstrikeQuery(p, max); } catch (e) { return { ok: false, events: [], truncated: false, query, error: String((e as Error).message), durationMs: 0 }; }
      const t = await token();
      if ("error" in t) return { ok: false, events: [], truncated: false, query, error: t.error, durationMs: took() };
      const auth = { Authorization: `Bearer ${t.token}` };
      const start = await http(jobs, { method: "POST", headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify({ queryString: query, start: p.start.getTime(), end: p.end.getTime(), isLive: false }) }, s.timeoutMs);
      const id = isRecord(start.json) ? str(start.json.id) : undefined;
      if (start.status !== 200 || !id) return { ok: false, events: [], truncated: false, query, error: describeFailure("CrowdStrike", start), durationMs: took() };
      const deadline = Date.now() + s.timeoutMs;
      try {
        for (let delay = s.pollMs ?? 400; ; delay = Math.min(delay * 2, 3000)) {
          const poll = await http(`${jobs}/${encodeURIComponent(id)}`, { method: "GET", headers: auth }, Math.max(1000, deadline - Date.now()));
          if (poll.status !== 200 || !isRecord(poll.json)) return { ok: false, events: [], truncated: false, query, error: describeFailure("CrowdStrike", poll), durationMs: took() };
          if (poll.json.cancelled === true) return { ok: false, events: [], truncated: false, query, error: "CrowdStrike cancelled the search.", durationMs: took() };
          if (poll.json.done === true) {
            const events = (Array.isArray(poll.json.events) ? poll.json.events : []).filter(isRecord).map(crowdstrikeEvent);
            const meta = isRecord(poll.json.metaData) && isRecord(poll.json.metaData.extraData) ? poll.json.metaData.extraData : {};
            return { ok: true, events, truncated: meta.hasMoreEvents === true || meta.hasMoreEvents === "true" || events.length >= max, query, durationMs: took() };
          }
          if (Date.now() + delay > deadline) return { ok: false, events: [], truncated: false, query, error: "CrowdStrike search did not finish in time.", durationMs: took() };
          await Bun.sleep(delay);
        }
      } finally {
        void http(`${jobs}/${encodeURIComponent(id)}`, { method: "DELETE", headers: auth }, 5000);
      }
    },
  };
}
