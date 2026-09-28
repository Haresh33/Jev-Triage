/**
 * Splunk Enterprise / Splunk Cloud Platform: POST /services/search/v2/jobs/export (SPL, streamed JSON rows).
 * Uses a Splunk authentication token (Authorization: Bearer). Field names follow the Common Information Model
 * (Endpoint.Processes, Network_Traffic, Network_Resolution, Authentication), with `host` as a fallback.
 * SPLUNK_BASE_SEARCH narrows the indexes searched (e.g. "index=edr OR index=wineventlog").
 */

import { describeFailure, http, isRecord, num, str } from "./http";
import { assertSafe, quoted } from "./safety";
import type { LogEvent, LogSource, Pivot } from "./types";

export type SplunkSettings = { url: string; token: string; baseSearch: string; timeoutMs: number };

const FIELDS = "_time host dest user src_user process process_name parent_process parent_process_name process_hash file_hash src src_ip dest_ip dest_port query url_domain action signature tag sourcetype";
const hostFilter = (h: string) => `(host=${quoted(h)} OR host=${quoted(`${h}.*`)} OR dest=${quoted(h)} OR dest=${quoted(`${h}.*`)})`;

/** The SPL for one pivot. `*` is added only by this code; alert values can't contain quotes, pipes or wildcards. */
export function splunkQuery(p: Pivot, base: string, max: number): string {
  let filter: string;
  switch (p.kind) {
    case "host_activity": filter = hostFilter(assertSafe("host", p.value)); break;
    case "process_tree": { const x = assertSafe("process", p.process ?? ""); filter = `${hostFilter(assertSafe("host", p.value))} (process_name=${quoted(x)} OR parent_process_name=${quoted(x)} OR process=${quoted(`*${x}*`)} OR parent_process=${quoted(`*${x}*`)})`; break; }
    case "user_activity": { const u = assertSafe("account", p.value); filter = `(user=${quoted(u)} OR user=${quoted(`*\\${u}`)} OR user=${quoted(`${u}@*`)} OR src_user=${quoted(u)})`; break; }
    case "hash_prevalence": filter = quoted(assertSafe("sha256", p.value)); break;
    case "ip_prevalence": { const ip = assertSafe("ip", p.value); filter = `(dest=${quoted(ip)} OR dest_ip=${quoted(ip)} OR ${quoted(ip)})`; break; }
    case "domain_prevalence": { const d = assertSafe("domain", p.value); filter = `(query=${quoted(d)} OR query=${quoted(`*.${d}`)} OR url_domain=${quoted(d)} OR ${quoted(d)})`; break; }
  }
  return `search ${base} ${filter} | head ${max} | table ${FIELDS}`;
}

export function splunkEvent(r: Record<string, unknown>): LogEvent {
  const tags = [str(r.tag) ?? "", ...(Array.isArray(r.tag) ? r.tag.map(String) : [])].join(" ");
  const category: LogEvent["category"] = /authentication/.test(tags) ? "logon" : r.query ? "dns" : r.process || r.process_name ? "process" : r.dest_port || r.dest_ip ? "network" : r.file_hash ? "file" : "other";
  const time = str(r._time) ?? "";
  return {
    time: /^\d+(\.\d+)?$/.test(time) ? new Date(Number(time) * 1000).toISOString() : time, category,
    host: str(r.dest) ?? str(r.host), user: str(r.user) ?? str(r.src_user), action: str(r.action) ?? str(r.signature),
    process: str(r.process_name), commandLine: str(r.process), parent: str(r.parent_process_name), parentCommandLine: str(r.parent_process),
    sha256: str(r.process_hash)?.match(/[a-f0-9]{64}/i)?.[0] ?? str(r.file_hash)?.match(/[a-f0-9]{64}/i)?.[0],
    srcIp: str(r.src_ip) ?? str(r.src), dstIp: str(r.dest_ip), dstPort: num(r.dest_port), domain: str(r.query) ?? str(r.url_domain),
    outcome: category === "logon" ? str(r.action) : undefined,
  };
}

/** The export endpoint streams one JSON object per line: rows under "result", errors under "messages". */
export function parseSplunkExport(text: string): { rows: Record<string, unknown>[]; errors: string[] } {
  const rows: Record<string, unknown>[] = []; const errors: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let o: unknown; try { o = JSON.parse(line); } catch { continue; }
    if (!isRecord(o)) continue;
    if (o.preview === true) continue;
    if (isRecord(o.result)) rows.push(o.result);
    if (Array.isArray(o.results)) rows.push(...o.results.filter(isRecord));
    if (Array.isArray(o.messages)) for (const m of o.messages) if (isRecord(m) && /error|fatal/i.test(String(m.type))) errors.push(String(m.text).slice(0, 200));
  }
  return { rows, errors };
}

export function splunkSource(s: SplunkSettings): LogSource {
  return {
    provider: "splunk",
    async search(p, max) {
      const started = performance.now(); let query = "";
      try { query = splunkQuery(p, s.baseSearch, max); } catch (e) { return { ok: false, events: [], truncated: false, query, error: String((e as Error).message), durationMs: 0 }; }
      const body = new URLSearchParams({ search: query, earliest_time: String(p.start.getTime() / 1000), latest_time: String(p.end.getTime() / 1000), output_mode: "json" });
      const r = await http(`${s.url}/services/search/v2/jobs/export`, { method: "POST", headers: { Authorization: `Bearer ${s.token}`, "Content-Type": "application/x-www-form-urlencoded" }, body }, s.timeoutMs);
      const durationMs = Math.round(performance.now() - started);
      if (r.status !== 200) return { ok: false, events: [], truncated: false, query, error: describeFailure("Splunk", r), durationMs };
      const { rows, errors } = parseSplunkExport(r.text);
      if (!rows.length && errors.length) return { ok: false, events: [], truncated: false, query, error: `Splunk: ${errors[0]}`, durationMs };
      const events = rows.map(splunkEvent);
      return { ok: true, events, truncated: events.length >= max, query, durationMs };
    },
  };
}
