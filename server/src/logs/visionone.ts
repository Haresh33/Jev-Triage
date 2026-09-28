/**
 * Trend Vision One search API v3.0: GET /v3.0/search/endpointActivities with the query in the TMV1-Query header.
 * Auth: Authorization: Bearer <API key>; the key's role needs "XDR Data Explorer: View queries…, and filter and
 * search queries". Times are ISO 8601 without milliseconds; `top` must be 50, 100, 500, 1000 or 5000.
 */

import { describeFailure, http, isRecord, num, str } from "./http";
import { assertSafe, isoSeconds, quoted } from "./safety";
import type { LogEvent, LogSource, Pivot } from "./types";

export type VisionOneSettings = { baseUrl: string; token: string; timeoutMs: number };

const SELECT = "eventTime,eventId,eventSubId,endpointHostName,logonUser,objectUser,processName,processCmd,parentName,parentCmd,objectCmd,objectFileHashSha256,processFileHashSha256,src,dst,dpt,request,objectHostName";

/** The TMV1-Query for one pivot (max 2048 characters). */
export function visionOneQuery(p: Pivot): string {
  switch (p.kind) {
    case "host_activity": return `endpointHostName:${quoted(assertSafe("host", p.value))} and (eventId:"1" or eventId:"3" or eventId:"4")`;
    case "process_tree": { const x = quoted(assertSafe("process", p.process ?? "")); return `endpointHostName:${quoted(assertSafe("host", p.value))} and eventId:"1" and (processCmd:${x} or parentCmd:${x} or objectCmd:${x})`; }
    case "user_activity": { const u = quoted(assertSafe("account", p.value)); return `logonUser:${u} or objectUser:${u}`; }
    case "hash_prevalence": { const h = quoted(assertSafe("sha256", p.value)); return `objectFileHashSha256:${h} or processFileHashSha256:${h}`; }
    case "ip_prevalence": { const ip = quoted(assertSafe("ip", p.value)); return `dst:${ip} or objectIps:${ip}`; }
    case "domain_prevalence": { const d = quoted(assertSafe("domain", p.value)); return `objectHostName:${d} or request:${d}`; }
  }
}

export function visionOneEvent(e: Record<string, unknown>): LogEvent {
  const id = num(e.eventId); const sub = num(e.eventSubId);
  const category: LogEvent["category"] = id === 1 ? "process" : id === 4 ? "dns" : id === 3 || id === 7 ? "network" : id === 6 ? "logon" : id === 2 ? "file" : "other";
  const t = num(e.eventTime);
  const base = (v: unknown) => str(v)?.replace(/^"/, "").split(/["\s]/)[0]?.split(/[\\/]/).pop();
  return {
    time: t ? new Date(t).toISOString() : str(e.eventTimeDT) ?? "", category, action: sub !== undefined ? `event ${id}/${sub}` : undefined,
    host: str(e.endpointHostName), user: str(e.logonUser) ?? str(e.objectUser),
    process: str(e.processName) ?? base(e.objectCmd ?? e.processCmd), commandLine: str(e.objectCmd) ?? str(e.processCmd),
    parent: str(e.parentName) ?? base(e.parentCmd ?? (e.objectCmd ? e.processCmd : undefined)), parentCommandLine: str(e.parentCmd) ?? (e.objectCmd ? str(e.processCmd) : undefined),
    sha256: str(e.objectFileHashSha256) ?? str(e.processFileHashSha256), srcIp: str(e.src), dstIp: str(e.dst), dstPort: num(e.dpt),
    domain: str(e.objectHostName) ?? (str(e.request) ? str(e.request)!.replace(/^[a-z]+:\/\//i, "").split(/[/:]/)[0] : undefined),
  };
}

export function visionOneSource(s: VisionOneSettings): LogSource {
  return {
    provider: "visionone",
    async search(p, max) {
      const started = performance.now(); let query = "";
      try { query = visionOneQuery(p); } catch (e) { return { ok: false, events: [], truncated: false, query, error: String((e as Error).message), durationMs: 0 }; }
      const top = [50, 100, 500, 1000, 5000].find((n) => n >= max) ?? 5000;
      const params = new URLSearchParams({ startDateTime: isoSeconds(p.start), endDateTime: isoSeconds(p.end), top: String(top), select: SELECT });
      const r = await http(`${s.baseUrl}/v3.0/search/endpointActivities?${params}`, { method: "GET", headers: { Authorization: `Bearer ${s.token}`, "TMV1-Query": query } }, s.timeoutMs);
      const durationMs = Math.round(performance.now() - started);
      if (r.status !== 200 || !isRecord(r.json) || !Array.isArray(r.json.items)) return { ok: false, events: [], truncated: false, query, error: describeFailure("Vision One", r), durationMs };
      const events = r.json.items.filter(isRecord).map(visionOneEvent).sort((a, b) => b.time.localeCompare(a.time)).slice(0, max);
      return { ok: true, events, truncated: Boolean(r.json.nextLink) || r.json.items.length > max, query, durationMs };
    },
  };
}
